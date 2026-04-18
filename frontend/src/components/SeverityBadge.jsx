const STYLES = {
  critical: 'bg-[#2d171a] text-[#ffb3bb] border-[#5f2129]',
  high: 'bg-[#2e1d12] text-[#ffc896] border-[#5f3516]',
  medium: 'bg-[#2b2612] text-[#f5dd8b] border-[#5a4d18]',
  low: 'bg-[#16243a] text-[#a9c8ff] border-[#224d91]',
}

export default function SeverityBadge({ severity, count, dot = false }) {
  const sev = (severity || 'low').toLowerCase()
  const cls = STYLES[sev] || STYLES.low
  return (
    <span
      className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${cls}`}
    >
      {dot && (
        <span
          className="h-1.5 w-1.5"
          style={{
            background:
              sev === 'critical'
                ? '#da1e28'
                : sev === 'high'
                ? '#ff832b'
                : sev === 'medium'
                ? '#f1c21b'
                : '#0f62fe',
          }}
        />
      )}
      <span>{sev}</span>
      {typeof count === 'number' && (
        <span className="ml-0.5 font-semibold tabular-nums">{count}</span>
      )}
    </span>
  )
}
