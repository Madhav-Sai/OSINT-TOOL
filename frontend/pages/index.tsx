import { useState } from 'react'

export default function Home() {
  const [value, setValue] = useState('')
  const [hash, setHash] = useState('')
  const [algo, setAlgo] = useState('sha256')
  const [loading, setLoading] = useState(false)
  const [metaLoading, setMetaLoading] = useState(false)
  const [metaResult, setMetaResult] = useState<any | null>(null)

  async function compute() {
    setLoading(true)
    try {
      const res = await fetch('http://localhost:8000/api/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm: algo, value })
      })
      const data = await res.json()
      setHash(data.hash ?? JSON.stringify(data))
    } catch (e) {
      setHash('error')
    } finally {
      setLoading(false)
    }
  }

  async function uploadMetadata(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setMetaLoading(true)
    setMetaResult(null)
    setMetaResult({ progress: [] })

    const jobId = `job-${Date.now()}-${Math.floor(Math.random()*1e6)}`
    const evt = new EventSource(`http://localhost:8000/events/metadata/${jobId}`)
    evt.onmessage = (ev) => {
      const msg = ev.data
      setMetaResult(prev => {
        const p = (prev && (prev as any).progress) ? (prev as any).progress.slice() : []
        p.push(msg)
        return { ...(prev || {}), progress: p }
      })
    }
    evt.onerror = () => { /* ignore */ }

    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('job_id', jobId)
      const res = await fetch('http://localhost:8000/api/metadata', { method: 'POST', body: fd })
      const data = await res.json()
      setMetaResult(prev => ({ ...(prev || {}), response: data }))
    } catch (err) {
      setMetaResult(prev => ({ ...(prev || {}), error: 'upload failed' }))
    } finally {
      setMetaLoading(false)
      try { evt.close() } catch(e) {}
    }
  }

  return (
    <main className="min-h-screen text-white p-8" style={{backgroundImage: 'radial-gradient(800px at 10% 10%, rgba(0,229,255,0.03), transparent), radial-gradient(600px at 90% 80%, rgba(255,59,168,0.03), transparent)'}}>
      <div className="container">
        <header className="site-header">
          <div>
            <div className="site-title">OSINT-TOOL</div>
            <div className="site-sub">Glass-Neon demo • Node + Python worker</div>
          </div>
          <div>
            <button className="sign-in">Sign in</button>
          </div>
        </header>

        <section className="two-col">
          <div className="glass p-6">
            <div className="card-heading">Hash Tool</div>
            <div className="mb-3">
              <label className="block mb-2 text-sm">Enter text to hash</label>
              <textarea value={value} onChange={e => setValue(e.target.value)} rows={5} className="w-full glass-input" />
            </div>
            <div className="mb-4">
              <label className="block mb-2 text-sm">Algorithm</label>
              <select value={algo} onChange={e => setAlgo(e.target.value)} className="w-full glass-input">
                <option>sha256</option>
                <option>sha1</option>
                <option>md5</option>
              </select>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={compute} disabled={loading} className="neon-btn">{loading ? 'Computing...' : 'Compute'}</button>
              <div className="text-xs text-slate-400">Result will appear below</div>
            </div>
            <div className="mt-4">
              <label className="block mb-2 text-sm">Result</label>
              <textarea readOnly value={hash} className="w-full glass-input h-28" />
            </div>
          </div>

          <div className="glass p-6">
            <div className="card-heading">Metadata Inspector</div>
            <div className="mb-3 text-sm text-slate-300">Upload an image, PDF, document, or audio/video file to extract metadata.</div>
            <input type="file" onChange={uploadMetadata} className="mb-3" />
            {metaLoading && <div className="text-sm">Extracting…</div>}
            {metaResult && (
              <div className="mt-3">
                <div className="text-sm mb-2">Progress</div>
                <div className="text-xs text-slate-400 mb-2">{(metaResult as any).progress?.join(' → ')}</div>
                <div className="text-sm mb-2">Response</div>
                <pre className="meta-json">{JSON.stringify((metaResult as any).response || metaResult, null, 2)}</pre>
              </div>
            )}
          </div>
        </section>
      </div>
    </main>
  )
}
