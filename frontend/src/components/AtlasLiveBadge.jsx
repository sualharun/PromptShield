import { useEffect, useRef, useState } from 'react'

/**
 * AtlasLiveBadge — subscribes to /api/live/scans (MongoDB Atlas change stream
 * over a WebSocket) and shows a pulsing green dot whenever a new scan lands.
 *
 * Click (or focus) the badge to reveal a popover with last-scan details and
 * a tiny rolling buffer of the last few events — pitch-friendly proof that
 * the change stream is actually wired up.
 */
export default function AtlasLiveBadge({ source = null }) {
  const [status, setStatus] = useState('connecting')
  const [lastScan, setLastScan] = useState(null)
  const [recent, setRecent] = useState([]) // last N scans, newest first
  const [pulse, setPulse] = useState(false)
  const [open, setOpen] = useState(false)
  const wsRef = useRef(null)
  const pulseTimer = useRef(null)
  const wrapRef = useRef(null)

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const apiBase = import.meta.env?.VITE_API_BASE_URL || ''
    const host = apiBase
      ? apiBase.replace(/^http/, 'ws')
      : `${proto}//${window.location.host}`
    const url = source
      ? `${host}/api/live/scans?source=${encodeURIComponent(source)}`
      : `${host}/api/live/scans`

    let ws
    try {
      ws = new WebSocket(url)
      wsRef.current = ws
    } catch {
      setStatus('unavailable')
      return
    }

    ws.onopen = () => setStatus('connected')
    ws.onclose = (ev) => {
      setStatus(ev.code === 1000 ? 'idle' : 'unavailable')
    }
    ws.onerror = () => setStatus('unavailable')
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'info') {
          setStatus('idle')
          return
        }
        if (msg.type === 'ready') {
          setStatus('connected')
          return
        }
        if (msg.type === 'error') {
          setStatus('unavailable')
          return
        }
        if (msg.scan) {
          const scanWithTs = { ...msg.scan, _received_at: Date.now() }
          setLastScan(scanWithTs)
          setRecent((prev) => [scanWithTs, ...prev].slice(0, 5))
          setPulse(true)
          clearTimeout(pulseTimer.current)
          pulseTimer.current = setTimeout(() => setPulse(false), 2500)
        }
      } catch {
        /* ignore */
      }
    }

    return () => {
      clearTimeout(pulseTimer.current)
      try {
        ws.close()
      } catch {
        /* ignore */
      }
    }
  }, [source])

  // Close on outside click
  useEffect(() => {
    if (!open) return
    function handle(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [open])

  const color =
    status === 'connected' ? '#13aa52' : status === 'unavailable' ? '#a2191f' : '#8d8d8d'
  const label =
    status === 'connected'
      ? 'Live'
      : status === 'unavailable'
        ? 'Live updates offline'
        : 'Idle'

  function ago(ts) {
    if (!ts) return ''
    const s = Math.max(1, Math.round((Date.now() - ts) / 1000))
    if (s < 60) return `${s}s ago`
    const m = Math.round(s / 60)
    if (m < 60) return `${m}m ago`
    return `${Math.round(m / 60)}h ago`
  }

  return (
    <span ref={wrapRef} className="relative inline-flex">
      <button
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-2 border border-carbon-border bg-white px-2 py-1 font-mono text-[10px] font-medium uppercase tracking-wider text-carbon-text-secondary transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
      >
        <span
          aria-hidden
          className={pulse ? 'animate-ping-slow' : ''}
          style={{
            display: 'inline-block',
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: color,
            boxShadow: pulse ? `0 0 0 4px ${color}33` : 'none',
            transition: 'box-shadow 200ms ease',
          }}
        />
        <span>Atlas · {label}</span>
        <span aria-hidden className="text-[10px] opacity-60">▾</span>
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Atlas change-stream details"
          className="absolute right-0 top-full z-40 mt-1 w-80 border border-carbon-border bg-white p-3 text-[11px] shadow-lg dark:border-ibm-gray-80 dark:bg-ibm-gray-90"
        >
          <div className="mb-2 flex items-center justify-between">
            <span className="font-semibold uppercase tracking-wider text-[#13aa52]">
              ◆ Atlas Change Stream
            </span>
            <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
              {status}
            </span>
          </div>
          <p className="mb-2 leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
            WebSocket bridge to a Mongo <code>watch()</code> on{' '}
            <code>scans</code>. New scans push here in real time — no polling.
          </p>
          {lastScan ? (
            <>
              <div className="mb-1 font-medium text-carbon-text dark:text-ibm-gray-10">
                Last scan ({ago(lastScan._received_at)})
              </div>
              <div className="mb-2 grid grid-cols-2 gap-x-2 gap-y-0.5 font-mono text-[10px] text-carbon-text-secondary dark:text-ibm-gray-30">
                <span className="opacity-60">risk</span>
                <span>{Math.round(lastScan.risk_score || 0)}</span>
                <span className="opacity-60">source</span>
                <span>{lastScan.source || 'web'}</span>
                {lastScan.repo_full_name && (
                  <>
                    <span className="opacity-60">repo</span>
                    <span className="truncate">{lastScan.repo_full_name}</span>
                  </>
                )}
                {lastScan.pr_number && (
                  <>
                    <span className="opacity-60">PR</span>
                    <span>#{lastScan.pr_number}</span>
                  </>
                )}
                {lastScan.id && (
                  <>
                    <span className="opacity-60">id</span>
                    <span className="truncate">
                      {String(lastScan.id).slice(0, 12)}…
                    </span>
                  </>
                )}
              </div>
              {recent.length > 1 && (
                <>
                  <div className="mb-1 mt-2 font-medium text-carbon-text dark:text-ibm-gray-10">
                    Recent ({recent.length})
                  </div>
                  <ul className="space-y-0.5 font-mono text-[10px] text-carbon-text-secondary dark:text-ibm-gray-30">
                    {recent.map((s) => (
                      <li key={s.id || s._received_at} className="flex justify-between gap-2">
                        <span className="truncate">
                          {s.repo_full_name || s.source || 'web'}
                          {s.pr_number ? ` #${s.pr_number}` : ''}
                        </span>
                        <span className="opacity-70">
                          risk {Math.round(s.risk_score || 0)} · {ago(s._received_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          ) : status === 'unavailable' ? (
            <p className="text-carbon-text-tertiary dark:text-ibm-gray-40">
              Atlas isn't reachable from this server (no <code>MONGODB_URI</code>?).
              The dashboard will still work; live updates are off.
            </p>
          ) : (
            <p className="text-carbon-text-tertiary dark:text-ibm-gray-40">
              Waiting for the next scan to arrive…
            </p>
          )}
        </div>
      )}
    </span>
  )
}
