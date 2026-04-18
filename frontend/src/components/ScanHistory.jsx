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
  if (s <= 30) return '#198038'
  if (s <= 60) return '#8a6800'
  if (s <= 85) return '#b8470c'
  return '#a2191f'
}

export default function ScanHistory({ scans = [], activeId, onSelect }) {
  return (
    <aside className="h-full w-full overflow-y-auto border-l border-carbon-border bg-carbon-layer scrollbar-thin dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
      <div className="border-b border-carbon-border bg-white px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Recent scans
        </h2>
        <p className="mt-0.5 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Last 10 · click to reload
        </p>
      </div>
      {scans.length === 0 ? (
        <p className="px-4 py-6 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
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
                  className={`w-full border-b border-carbon-border px-4 py-3 text-left transition-colors dark:border-ibm-gray-80 ${
                    active
                      ? 'border-l-2 border-l-ibm-blue-60 bg-white dark:bg-ibm-gray-90'
                      : 'border-l-2 border-l-transparent bg-carbon-layer hover:bg-white dark:bg-ibm-gray-100 dark:hover:bg-ibm-gray-90'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
                      <span>#{s.id}</span>
                      {s.source === 'github' && s.pr_number != null && (
                        <span className="border border-ibm-blue-60 bg-ibm-blue-10 px-1 py-px text-[9px] font-semibold uppercase tracking-wider text-ibm-blue-70 dark:bg-ibm-blue-90/40 dark:text-ibm-blue-30">
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
                    <span>{s.total_count} finding{s.total_count === 1 ? '' : 's'}</span>
                    {s.critical_count > 0 && (
                      <span className="text-[#a2191f]">
                        {s.critical_count} crit
                      </span>
                    )}
                    {s.high_count > 0 && (
                      <span className="text-[#b8470c]">{s.high_count} high</span>
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
