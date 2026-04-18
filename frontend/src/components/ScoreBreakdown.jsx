const CONFIDENCE_STYLES = {
  high: 'bg-ibm-green-60/10 text-ibm-green-60 border-ibm-green-60/40',
  medium: 'bg-ibm-yellow-60/10 text-[#b8470c] border-[#b8470c]/40',
  low: 'bg-ibm-gray-60/10 text-carbon-text-tertiary border-carbon-border',
}

function barColor(score) {
  if (score >= 80) return '#24a148'
  if (score >= 60) return '#f1c21b'
  if (score >= 40) return '#ff832b'
  return '#da1e28'
}

export default function ScoreBreakdown({ breakdown }) {
  if (!breakdown || !Array.isArray(breakdown.categories)) return null

  return (
    <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Score breakdown
        </h2>
        <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Higher = safer · 100 means no issues detected
        </span>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {breakdown.categories.map((c) => (
          <div key={c.key} className="border border-carbon-border p-4 dark:border-ibm-gray-80">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">
                {c.label}
              </span>
              <span
                className={`inline-flex items-center border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
                  CONFIDENCE_STYLES[c.confidence] || CONFIDENCE_STYLES.low
                }`}
              >
                {c.confidence} confidence
              </span>
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="font-light text-2xl tabular-nums text-carbon-text dark:text-ibm-gray-10">
                {c.score}
                <span className="ml-1 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                  /100
                </span>
              </span>
              <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                {c.finding_count} finding{c.finding_count === 1 ? '' : 's'}
              </span>
            </div>
            <div className="mt-2 h-2 w-full overflow-hidden border border-carbon-border dark:border-ibm-gray-80">
              <div
                className="h-full"
                style={{
                  width: `${Math.max(0, Math.min(100, c.score))}%`,
                  backgroundColor: barColor(c.score),
                }}
              />
            </div>
            <p className="mt-2 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
              {c.why}
            </p>
          </div>
        ))}
      </div>

      {Array.isArray(breakdown.signals) && breakdown.signals.length > 0 && (
        <div className="mt-4 border-t border-carbon-border pt-3 dark:border-ibm-gray-80">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Signal sources
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {breakdown.signals.map((s) => (
              <span
                key={s.source}
                className="inline-flex items-center gap-2 border border-carbon-border px-3 py-1 text-[11px] text-carbon-text-secondary dark:border-ibm-gray-80 dark:text-ibm-gray-30"
              >
                <span className="font-semibold uppercase tracking-wider">
                  {s.source}
                </span>
                <span className="tabular-nums">{s.weight_pct}%</span>
                <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
                  · {s.confidence}
                </span>
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
