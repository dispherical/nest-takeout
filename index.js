require("dotenv").config()
const express = require('express')
const app = express()
var { Liquid } = require('liquidjs');
var engine = new Liquid();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient()
const crypto = require('crypto');
const session = require('express-session');
const { PrismaSessionStore } = require('@quixo3/prisma-session-store');
const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')
const util = require('util')
const exec = util.promisify(require('child_process').exec)
const queue = require('./queue')
const mail = require('./mail')

const startdir = "/mnt/oldnest/home"

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use((req, res, next) => {
  if (req.query._method === 'DELETE') {
    req.method = 'DELETE'
    delete req.query._method
  }
  next()
})
app.use(express.static("./public"))
app.engine('liquid', engine.express());
app.set('views', './views');
app.set('view engine', 'liquid');

app.set('trust proxy', 1);
app.get('/', async (req, res) => {
  res.render("index")
})

app.use(session({
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? 'auto' : false,
    sameSite: 'lax'
  },
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: new PrismaSessionStore(
    prisma,
    {
      checkPeriod: 2 * 60 * 1000,
      dbRecordIdIsSessionId: true,
      dbRecordIdFunction: undefined,
    }
  ),
  proxy: true
}))

app.get('/auth/login', (req, res) => {
  res.render('login')
})

app.post('/auth/challenge', (req, res) => {
  const { username } = req.body
  if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(username)) return res.redirect('/auth/login')
  const challenge = crypto.randomBytes(32).toString('hex')
  req.session.challenge = challenge
  res.render('challenge', { username, challenge })
})

app.post('/auth/verify', async (req, res) => {
  const { username, signature } = req.body
  const expectedChallenge = req.session.challenge

  if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(username) || !signature || !expectedChallenge) {
    return res.status(400).send('Missing required fields')
  }

  const authKeysPath = path.join(startdir, username, '.ssh', 'authorized_keys')
  if (!fs.existsSync(authKeysPath)) {
    return res.status(403).send('User has no SSH keys')
  }

  const workDir = await fs.promises.mkdtemp(path.join(process.cwd(), 'tmp', 'ssh-auth-'))

  try {
    const dataFile = path.join(workDir, 'data')
    await fs.promises.writeFile(dataFile, expectedChallenge)

    let sigStr = signature.trim()
    const match = sigStr.match(/-----BEGIN SSH SIGNATURE-----[\s\S]*-----END SSH SIGNATURE-----/)
    if (match) sigStr = match[0]

    const sigFile = path.join(workDir, 'data.sig')
    await fs.promises.writeFile(sigFile, sigStr)

    const keys = await fs.promises.readFile(authKeysPath, 'utf8')
    const allowedSigners = keys
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .map(line => `${username} ${line}`)
      .join('\n')

    const allowedSignersFile = path.join(workDir, 'allowed_signers')
    await fs.promises.writeFile(allowedSignersFile, allowedSigners)

    await exec(`ssh-keygen -Y verify -f ${allowedSignersFile} -I ${username} -n file -s ${sigFile} - < ${dataFile}`)

    req.session.user = {
      preferred_username: username,
      email: `${username}@nest.hackclub.app`,
      name: username
    }
    delete req.session.challenge
    res.redirect('/dashboard')
  } catch (err) {
    console.error('verify failed:', err.stderr?.toString(), err.stdout?.toString())
    res.status(403).send('Invalid signature')
  } finally {
    await fs.promises.rm(workDir, { recursive: true, force: true }).catch(() => { })
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/')
  })
})

app.get('/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'unauthorized' })
  res.json(req.session.user)
})

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/auth/login')
  next()
}

app.get('/dashboard', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username || ''
  let job = null
  let position = null
  let queueDepth = null
  if (username) {
    job = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
    if (job && (job.status === 'queued' || job.status === 'processing')) {
      position = await queue.getPosition(job.id)
      queueDepth = (await queue.getStats()).total
    }
  }
  res.render('dashboard', { user: req.session.user, job, position, queueDepth })
})

function ensureDir(p) {
  return fs.promises.mkdir(p, { recursive: true })
}

async function processZipJob(job) {
  const { id: jobId, username } = job
  const baseDir = path.join(process.cwd(), 'tmp', 'zips')
  await ensureDir(baseDir)
  const timestamp = Date.now()
  const archivePath = path.join(baseDir, `${username}-${timestamp}.tar`)
  await prisma.zipJob.update({
    where: { id: jobId },
    data: { filePath: archivePath, progress: 0 }
  })
  const srcDir = path.join(startdir, username)
  if (!fs.existsSync(srcDir)) {
    await prisma.zipJob.update({
      where: { id: jobId },
      data: { status: 'error', error: 'source directory not found' }
    })
    console.error('source directory not found')
    return
  }

  const excludes = [
    'node_modules', '.npm', '.yarn/cache', '.pnpm-store',
    '.bun/install/cache', '.cargo/registry', '.rustup',
    '__pycache__', '.venv', 'venv',
    '.cache', '.local/share/Trash'
  ]
  const excludeArgs = excludes.map(p => `--exclude=${p}`)

  let totalBytes = null
  exec(`du -sb ${excludeArgs.join(' ')} ${JSON.stringify(srcDir)}`)
    .then(({ stdout }) => {
      const n = parseInt(stdout.split(/\s+/)[0], 10)
      if (Number.isFinite(n) && n > 0) totalBytes = n
    })
    .catch(() => { })

  const poll = setInterval(async () => {
    try {
      const st = await fs.promises.stat(archivePath)
      if (totalBytes) {
        const pct = Math.min(99, Math.floor((st.size / totalBytes) * 100))
        await prisma.zipJob.update({ where: { id: jobId }, data: { progress: pct } })
      }
    } catch { }
  }, 3000)

  return new Promise((resolve) => {
    const tarProc = spawn('tar', [
      '--warning=no-file-changed',
      '--warning=no-file-removed',
      '--ignore-failed-read',
      ...excludeArgs,
      '-cf', archivePath,
      '-C', startdir, username
    ])

    tarProc.on('error', async (e) => {
      clearInterval(poll)
      await prisma.zipJob.update({
        where: { id: jobId },
        data: { status: 'error', error: String(e?.message || e) }
      })
      console.error(`tar process error: ${e.message}`)
      resolve()
    })

    tarProc.on('exit', async (code, signal) => {
      clearInterval(poll)
      if (code === 0 || code === 1) {
        const now = new Date()
        const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000)
        await prisma.zipJob.update({
          where: { id: jobId },
          data: { status: 'complete', progress: 100, completedAt: now, expiresAt: expires }
        })
        try {
          const fresh = await prisma.zipJob.findUnique({ where: { id: jobId } })
          if (fresh?.email && !fresh.notifiedAt) {
            await mail.sendCompletionEmail({
              to: fresh.email,
              username,
              expiresAt: expires,
            })
            await prisma.zipJob.update({
              where: { id: jobId },
              data: { notifiedAt: new Date() }
            })
          }
        } catch (e) {
          console.error(`[mail] send failed for ${username}: ${e.message}`)
        }
      } else {
        const reason = signal ? `killed by ${signal}` : `exit code ${code}`
        await prisma.zipJob.update({
          where: { id: jobId },
          data: { status: 'error', error: `tar ${reason}` }
        })
        console.error(`tar ${reason}`)
      }
      resolve()
    })
  })
}

function hasActiveJob(job) {
  if (!job) return false
  return job.status === 'queued' || job.status === 'processing' || job.status === 'complete'
}

app.post('/zip/start', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username
  if (!username) return res.redirect('/dashboard')
  const email = (req.body.email || '').trim()
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).send('Valid email required')
  }
  const existing = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  if (hasActiveJob(existing)) return res.redirect('/dashboard')
  await prisma.zipJob.create({ data: { username, email, status: 'queued', progress: 0 } })
  queue.tick()
  res.redirect('/dashboard')
})

app.get('/zip/status', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username
  if (!username) return res.status(400).json({ error: 'missing username' })
  const job = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  if (!job) return res.json({ status: 'none' })
  const out = {
    status: job.status,
    progress: job.progress,
    expiresAt: job.expiresAt,
    completedAt: job.completedAt,
    error: job.error
  }
  if (job.status === 'queued' || job.status === 'processing') {
    const [position, stats] = await Promise.all([
      queue.getPosition(job.id),
      queue.getStats()
    ])
    out.position = position
    out.queueDepth = stats.total
  }
  res.json(out)
})

app.get('/zip/download', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username
  if (!username) return res.redirect('/dashboard')
  const job = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  if (!job || job.status !== 'complete' || !job.filePath) return res.redirect('/dashboard')
  const now = new Date()
  if (job.expiresAt && now > job.expiresAt) {
    if (job.filePath) {
      fs.promises.unlink(job.filePath).catch(() => { })
    }
    await prisma.zipJob.update({ where: { id: job.id }, data: { status: 'expired' } })
    return res.redirect('/dashboard')
  }
  if (!fs.existsSync(job.filePath)) return res.redirect('/dashboard')
  res.download(job.filePath, `${username}-home.tar`)
})

async function cleanupExpiredZips() {
  const now = new Date()
  const jobs = await prisma.zipJob.findMany({ where: { status: 'complete', expiresAt: { lt: now } } })
  for (const job of jobs) {
    if (job.filePath) {
      await fs.promises.unlink(job.filePath).catch(() => { })
    }
    await prisma.zipJob.update({ where: { id: job.id }, data: { status: 'expired' } })
  }
}

setInterval(() => {
  cleanupExpiredZips().catch(() => { })
}, 60 * 60 * 1000)

queue.setProcessor(processZipJob)
queue.recover().then(() => queue.tick())

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`nest export is listening on port ${port}`)
})
