import SeverityBadge from './SeverityBadge.jsx'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

export default function FindingsToolbar({
  counts,
  activeSeverities,
  onToggleSeverity,
  onClear,
  query,
  onQuery,
  total,
  shown,
}) {
  return (
    <div className="sticky top-0 z-20 border border-carbon-border bg-carbon-layer/95 backdrop-blur dark:border-ibm-gray-80 dark:bg-ibm-gray-100/95">
      <div className="flex flex-wrap items-center gap-3 border-b border-carbon-border px-4 py-3 dark:border-ibm-gray-80">
        <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Filter
        </span>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((sev) => {
            const active = activeSeverities.includes(sev)
            const c = counts[sev] || 0
            return (
              <button
                key={sev}
                type="button"
                onClick={() => onToggleSeverity(sev)}
                className={`transition-opacity ${
                  active ? 'opacity-100' : 'opacity-40 hover:opacity-70'
                }`}
                aria-pressed={active}
              >
                <SeverityBadge severity={sev} count={c} dot />
              </button>
            )
          })}
        </div>
        {(activeSeverities.length < SEVERITIES.length || query) && (
          <button
            type="button"
            onClick={onClear}
            className="ml-auto text-[12px] font-medium text-ibm-blue-70 hover:text-ibm-blue-80 dark:text-ibm-blue-30 dark:hover:text-ibm-blue-20"
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="flex items-center gap-3 px-4 py-2">
        <input
          type="search"
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          placeholder="Search findings by title, type, CWE, evidence..."
          className="w-full border border-carbon-border bg-carbon-bg px-3 py-2 text-sm text-carbon-text placeholder:text-carbon-text-tertiary focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:text-ibm-gray-10 dark:placeholder:text-ibm-gray-50"
        />
        <span className="whitespace-nowrap font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          {shown} / {total}
        </span>
      </div>
    </div>
  )
}
