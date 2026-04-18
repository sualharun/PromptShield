/**
 * SearchHighlights — render the `highlights` array Atlas $search returns
 * (`{$meta: 'searchHighlights'}` projection).
 *
 * Each highlight has shape: { path, score, texts: [{value, type}] } where
 * type === 'hit' marks the matched span. We re-render with <mark> spans so
 * judges can see Atlas Search actually matched specific tokens.
 */
export default function SearchHighlights({ highlights, max = 3 }) {
  if (!highlights || highlights.length === 0) return null
  const slice = highlights.slice(0, max)
  return (
    <div className="space-y-1">
      {slice.map((h, i) => (
        <div
          key={`${h.path}-${i}`}
          className="font-mono text-[11px] leading-snug text-carbon-text-secondary dark:text-ibm-gray-30"
        >
          <span className="mr-2 inline-block border border-[#13aa52] bg-[#13aa52]/10 px-1 py-px font-semibold uppercase tracking-wider text-[#13aa52]">
            {h.path}
          </span>
          {(h.texts || []).map((t, j) =>
            t.type === 'hit' ? (
              <mark
                key={j}
                className="bg-[#fff7c2] px-0.5 text-carbon-text dark:bg-[#5a4f00] dark:text-ibm-gray-10"
              >
                {t.value}
              </mark>
            ) : (
              <span key={j}>{t.value}</span>
            ),
          )}
        </div>
      ))}
    </div>
  )
}
