const express = require('express')
const multer = require('multer')
const crypto = require('crypto')
const { spawn } = require('child_process')
const path = require('path')
const fs = require('fs')
const cors = require('cors')

const app = express()
const upload = multer({ dest: path.join(__dirname, 'tmp') })
app.use(express.json())
app.use(cors())

const IORedis = require('ioredis')
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379'
const redis = new IORedis(REDIS_URL)


app.get('/health', (req, res) => res.json({ status: 'ok' }))

app.post('/api/hash', (req, res) => {
  const { algorithm = 'sha256', value = '' } = req.body || {}
  try {
    const h = crypto.createHash(algorithm)
    h.update(String(value))
    return res.json({ algorithm, hash: h.digest('hex') })
  } catch (e) {
    return res.status(400).json({ error: 'unsupported algorithm' })
  }
})

app.post('/api/hash_file', upload.single('file'), (req, res) => {
  const algorithm = req.body.algorithm || 'sha256'
  const file = req.file
  if (!file) return res.status(400).json({ error: 'file required' })
  const stream = fs.createReadStream(file.path)
  const h = crypto.createHash(algorithm)
  stream.on('data', (chunk) => h.update(chunk))
  stream.on('end', () => {
    const result = h.digest('hex')
    fs.unlink(file.path, () => {})
    res.json({ algorithm, filename: file.originalname, hash: result })
  })
  stream.on('error', (err) => res.status(500).json({ error: err.message }))
})

// metadata: calls Python worker script (backend/python_worker.py)
app.post('/api/metadata', upload.single('file'), (req, res) => {
  const file = req.file
  if (!file) return res.status(400).json({ error: 'file required' })
  // enqueue job into Redis job_queue
  const provided = (req.body && req.body.job_id) ? req.body.job_id : null
  const jobId = provided || `job-${Date.now()}-${Math.floor(Math.random()*1e6)}`
  const job = { id: jobId, mode: 'metadata', args: { path: file.path, orig_name: file.originalname } }
  redis.rpush('job_queue', JSON.stringify(job)).then(() => {
    res.json({ jobId })
  }).catch(err => {
    fs.unlink(file.path, () => {})
    res.status(500).json({ error: 'failed to enqueue job' })
  })
})


// Subdomains endpoint
app.post('/api/subdomains', express.json(), (req, res) => {
  const { domain } = req.body || {}
  if (!domain) return res.status(400).json({ error: 'domain required' })
  const jobId = `job-${Date.now()}-${Math.floor(Math.random()*1e6)}`
  const job = { id: jobId, mode: 'subdomains', args: { domain } }
  redis.rpush('job_queue', JSON.stringify(job)).then(() => {
    res.json({ jobId })
  }).catch(err => res.status(500).json({ error: 'failed to enqueue job' }))
})


// Reputation endpoint
app.post('/api/reputation', express.json(), (req, res) => {
  const { target } = req.body || {}
  if (!target) return res.status(400).json({ error: 'target required' })
  const jobId = `job-${Date.now()}-${Math.floor(Math.random()*1e6)}`
  const job = { id: jobId, mode: 'reputation', args: { target } }
  redis.rpush('job_queue', JSON.stringify(job)).then(() => {
    res.json({ jobId })
  }).catch(err => res.status(500).json({ error: 'failed to enqueue job' }))
})

const port = process.env.PORT || 8000
app.listen(port, () => console.log(`Node backend listening on ${port}`))

// --- SSE helpers for metadata progress ---
const SSE_SUBSCRIBERS = {} // jobId => [res]

function jobIdFromReq(req) {
  // attempt to read job_id from body/form; in metadata request we expect job_id form field
  return (req && req.body && req.body.job_id) || (req && req.query && req.query.job_id) || null
}

function broadcastSSE(jobId, msg) {
  if (!jobId) return
  const list = SSE_SUBSCRIBERS[jobId] || []
  list.forEach(res => {
    try {
      res.write(`data: ${msg}\n\n`)
    } catch (e) {
      // ignore
    }
  })
}

app.get('/events/metadata/:jobId', async (req, res) => {
  const jobId = req.params.jobId
  // headers for SSE
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  })
  res.flushHeaders()
  // send initial ping
  res.write('event: connected\n')
  res.write('data: connected\n\n')

  const channel = `job:${jobId}`
  const sub = new IORedis(REDIS_URL)
  await sub.subscribe(channel)
  const onMessage = (chan, message) => {
    if (chan !== channel) return
    try {
      const parsed = JSON.parse(message)
      res.write(`data: ${JSON.stringify(parsed)}\n\n`)
    } catch (e) {
      res.write(`data: ${message}\n\n`)
    }
  }
  sub.on('message', onMessage)

  req.on('close', () => {
    sub.unsubscribe(channel).catch(()=>{})
    sub.quit().catch(()=>{})
  })
})
