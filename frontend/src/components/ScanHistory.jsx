function fmt(ts) {
  try {
    const d = new Date(ts)
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return ts
  }
}

function scoreColor(s) {
  if (s <= 30) return '#5ec8ff'
  if (s <= 60) return '#ffd86e'
  if (s <= 85) return '#ff9b52'
  return '#ff5b73'
}

export default function ScanHistory({ scans = [], activeId, onSelect }) {
  return (
    <aside className="terminal-panel h-full w-full overflow-y-auto border-l border-carbon-border scrollbar-thin">
      <div className="border-b border-white/8 px-4 py-3">
        <h2 className="terminal-label text-[10px] font-semibold">
          Recent scans
        </h2>
        <p className="mt-0.5 text-[11px] text-[#8da7cd]">
          Last 10 · click to reload
        </p>
      </div>
      {scans.length === 0 ? (
        <p className="px-4 py-6 text-sm text-[#8da7cd]">
          No scans yet.
        </p>
      ) : (
        <ul>
          {scans.map((s) => {
            const active = s.id === activeId
            return (
              <li key={s.id}>
                <button
                  onClick={() => onSelect?.(s.id)}
                  className={`terminal-mono w-full border-b border-white/8 px-4 py-3 text-left transition-colors ${
                    active
                      ? 'border-l-2 border-l-[#5ea8ff] bg-white/6'
                      : 'border-l-2 border-l-transparent bg-transparent hover:bg-white/4'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-[11px] text-[#bfd0ef]">
                      <span>#{s.id}</span>
                      {s.source === 'github' && s.pr_number != null && (
                        <span className="border border-[#5ea8ff]/25 bg-[#5ea8ff]/10 px-2 py-px text-[9px] font-semibold uppercase tracking-wider text-[#a6d8ff]">
                          PR #{s.pr_number}
                        </span>
                      )}
                      <span>· {fmt(s.created_at)}</span>
                    </span>
                    <span
                      className="font-mono text-base font-semibold tabular-nums"
                      style={{ color: scoreColor(s.risk_score) }}
                    >
                      {s.risk_score}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[11px] text-carbon-text-tertiary">
                    <span className="text-[#8da7cd]">{s.total_count} finding{s.total_count === 1 ? '' : 's'}</span>
                    {s.critical_count > 0 && (
                      <span className="text-[#ff8a9b]">
                        {s.critical_count} crit
                      </span>
                    )}
                    {s.high_count > 0 && (
                      <span className="text-[#ffc18a]">{s.high_count} high</span>
                    )}
                  </div>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </aside>
  )
}
