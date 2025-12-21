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
let Issuer
let generators
const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')

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
let oidcClient
let oidcInitialized = false
async function initOIDC() {
  if (!Issuer || !generators) {
    const mod = await import('openid-client')
    Issuer = mod.Issuer
    generators = mod.generators
  }
  const baseIssuer = process.env.AUTH_ISSUER || 'https://identity.hackclub.app'
  const discovery = process.env.AUTH_DISCOVERY_URL || `${baseIssuer}/.well-known/openid-configuration`
  const issuer = await Issuer.discover(discovery)
  oidcClient = new issuer.Client({
    client_id: process.env.AUTH_CLIENT_ID,
    client_secret: process.env.AUTH_CLIENT_SECRET,
    redirect_uris: [process.env.AUTH_REDIRECT_URI || 'http://lg.hackclub.app/auth/callback'],
    response_types: ['code'],
    id_token_signed_response_alg: process.env.AUTH_ID_TOKEN_ALG || 'HS256'
  })
  oidcInitialized = true
}

app.get('/auth/login', async (req, res, next) => {
  try {
    if (!oidcInitialized) await initOIDC()
    const state = generators.state()
    const nonce = generators.nonce()
    req.session.oauth_state = state
    req.session.oauth_nonce = nonce
    const authUrl = oidcClient.authorizationUrl({
      scope: 'openid profile email',
      state,
      nonce
    })
    res.redirect(authUrl)
  } catch (e) {
    next(e)
  }
})

app.get('/auth/callback', async (req, res, next) => {
  try {
    if (!oidcInitialized) await initOIDC()
    const params = oidcClient.callbackParams(req)
    const state = req.session.oauth_state
    const nonce = req.session.oauth_nonce
    const tokenSet = await oidcClient.callback(process.env.AUTH_REDIRECT_URI || 'http://lg.hackclub.app/auth/callback', params, { state, nonce })
    const userinfo = await oidcClient.userinfo(tokenSet.access_token)
    req.session.user = {
      sub: tokenSet.claims().sub,
      email: userinfo.email,
      name: userinfo.name || userinfo.preferred_username || '',
      picture: userinfo.picture || '',
      ...userinfo
    }
    delete req.session.oauth_state
    delete req.session.oauth_nonce
    res.redirect('/dashboard')
  } catch (e) {
    next(e)
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
  if (username) {
    job = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  }
  res.render('dashboard', { user: req.session.user, job })
})

function ensureDir(p) {
  return fs.promises.mkdir(p, { recursive: true })
}

async function processZipJob(jobId, username) {
  const baseDir = path.join(process.cwd(), 'tmp', 'zips')
  await ensureDir(baseDir)
  const timestamp = Date.now()
  const zipPath = path.join(baseDir, `${username}-${timestamp}.zip`)
  await prisma.zipJob.update({ where: { id: jobId }, data: { status: 'processing', filePath: zipPath, progress: 0 } })
  const srcDir = path.join('/home', username)
  if (!fs.existsSync(srcDir)) {
    await prisma.zipJob.update({ where: { id: jobId }, data: { status: 'error', error: 'source directory not found' } })
    return
  }
  return new Promise((resolve) => {
    const zipProc = spawn('zip', ['-r', zipPath, '.'], { cwd: srcDir })
    zipProc.on('error', async (e) => {
      await prisma.zipJob.update({ where: { id: jobId }, data: { status: 'error', error: String(e && e.message ? e.message : e) } })
      resolve()
    })
    zipProc.on('exit', async (code) => {
      if (code === 0) {
        const now = new Date()
        const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000)
        await prisma.zipJob.update({ where: { id: jobId }, data: { status: 'complete', progress: 100, completedAt: now, expiresAt: expires } })
      } else {
        await prisma.zipJob.update({ where: { id: jobId }, data: { status: 'error', error: `zip exit code ${code}` } })
      }
      resolve()
    })
  })
}

function hasActiveJob(job) {
  if (!job) return false
  return job.status === 'queued' || job.status === 'processing'
}

app.post('/zip/start', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username
  if (!username) return res.redirect('/dashboard')
  const existing = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  if (hasActiveJob(existing)) return res.redirect('/dashboard')
  const job = await prisma.zipJob.create({ data: { username, status: 'queued', progress: 0 } })
  processZipJob(job.id, username).catch(() => { })
  res.redirect('/dashboard')
})

app.get('/zip/status', requireAuth, async (req, res) => {
  const username = req.session.user.preferred_username
  if (!username) return res.status(400).json({ error: 'missing username' })
  const job = await prisma.zipJob.findFirst({ where: { username }, orderBy: { createdAt: 'desc' } })
  if (!job) return res.json({ status: 'none' })
  res.json({ status: job.status, progress: job.progress, expiresAt: job.expiresAt, completedAt: job.completedAt })
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
  res.download(job.filePath, `${username}-home.zip`)
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
const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`nest export is listening on port ${port}`)
})
