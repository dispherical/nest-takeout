const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()

const CONCURRENCY = parseInt(process.env.ZIP_CONCURRENCY || '1')

let running = 0
let ticking = false
let processor = null

function setProcessor(fn) { processor = fn }

async function tick() {
  if (ticking || !processor) return
  ticking = true
  try {
    while (running < CONCURRENCY) {
      const job = await prisma.zipJob.findFirst({
        where: { status: 'queued' }, orderBy: { createdAt: 'asc' }
      })
      if (!job) break
      const claim = await prisma.zipJob.updateMany({
        where: { id: job.id, status: 'queued' },
        data: { status: 'processing' }
      })
      if (claim.count === 0) continue
      running++
      Promise.resolve().then(() => processor(job))
        .catch(err => console.error(`[queue] job ${job.id} threw:`, err))
        .finally(() => { running--; tick() })
    }
  } finally { ticking = false }
}

async function recover() {
  const res = await prisma.zipJob.updateMany({
    where: { status: 'processing' },
    data: { status: 'error', error: 'server restarted mid-job' }
  })
  if (res.count > 0) console.log(`[queue] recovered ${res.count} orphaned job(s)`)
}

async function getPosition(jobId) {
  const job = await prisma.zipJob.findUnique({ where: { id: jobId } })
  if (!job) return null
  if (job.status === 'processing') return 0
  if (job.status !== 'queued') return null
  const ahead = await prisma.zipJob.count({
    where: {
      OR: [
        { status: 'processing' },
        { status: 'queued', createdAt: { lt: job.createdAt } }
      ]
    }
  })
  return ahead
}

async function getStats() {
  const [queued, processing] = await Promise.all([
    prisma.zipJob.count({ where: { status: 'queued' } }),
    prisma.zipJob.count({ where: { status: 'processing' } })
  ])
  return { queued, processing, total: queued + processing }
}

module.exports = { setProcessor, tick, recover, getPosition, getStats }
