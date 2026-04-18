import { useEffect, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

const SEVERITY_COLORS = {
  critical: '#a2191f',
  high: '#b8470c',
  medium: '#8a6800',
  low: '#198038',
}

/**
 * SearchFacets — chips for severity + CWE breakdown driven by
 * /api/v2/search/facets (which uses Atlas $searchMeta facets).
 *
 * When `query` is set, facets reflect that query's matched docs;
 * otherwise it shows the global distribution. Clicking a chip lets the
 * parent filter the active result set (via onSelect).
 */
export default function SearchFacets({ query = null, onSelect, active = {} }) {
  const [facets, setFacets] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const url = query
      ? `/api/v2/search/facets?q=${encodeURIComponent(query)}`
      : '/api/v2/search/facets'
    fetchWithTimeout(url)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((data) => {
        if (!cancelled) setFacets(data)
      })
      .catch(() => {
        if (!cancelled) setFacets(null)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [query])

  const sev = facets?.severityFacet?.buckets || []
  const cwe = facets?.cweFacet?.buckets || []

  if (loading && !facets) {
    return (
      <div className="border border-carbon-border bg-white px-3 py-2 text-[11px] text-carbon-text-tertiary dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-40">
        Loading Atlas Search facets…
      </div>
    )
  }

  if (!facets || (!sev.length && !cwe.length)) return null

  return (
    <div className="border border-carbon-border bg-white px-3 py-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-2 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider">
        <span className="text-[#13aa52]">◆ Atlas $searchMeta facets</span>
        <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
          {query ? `for "${query}"` : 'global'}
        </span>
      </div>

      {sev.length > 0 && (
        <div className="mb-1.5">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-carbon-text-tertiary dark:text-ibm-gray-40">
            severity
          </div>
          <div className="flex flex-wrap gap-1.5">
            {sev.map((b) => {
              const id = (b._id || '').toLowerCase()
              const isActive = active.severity === id
              return (
                <button
                  key={id || 'unknown'}
                  type="button"
                  onClick={() => onSelect?.({ key: 'severity', value: id })}
                  className={`inline-flex items-center gap-1 border px-2 py-0.5 font-mono text-[11px] transition-colors ${
                    isActive
                      ? 'border-ibm-blue-60 bg-ibm-blue-60 text-white'
                      : 'border-carbon-border bg-carbon-layer text-carbon-text-secondary hover:bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-90'
                  }`}
                >
                  <span
                    aria-hidden
                    className="inline-block h-1.5 w-1.5 rounded-full"
                    style={{
                      background: SEVERITY_COLORS[id] || '#525252',
                    }}
                  />
                  {id || 'unknown'}
                  <span className="opacity-70">· {b.count}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {cwe.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wider text-carbon-text-tertiary dark:text-ibm-gray-40">
            top CWEs
          </div>
          <div className="flex flex-wrap gap-1.5">
            {cwe.slice(0, 8).map((b) => {
              const isActive = active.cwe === b._id
              return (
                <button
                  key={b._id}
                  type="button"
                  onClick={() => onSelect?.({ key: 'cwe', value: b._id })}
                  className={`inline-flex items-center gap-1 border px-2 py-0.5 font-mono text-[11px] transition-colors ${
                    isActive
                      ? 'border-ibm-blue-60 bg-ibm-blue-60 text-white'
                      : 'border-carbon-border bg-carbon-layer text-carbon-text-secondary hover:bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-90'
                  }`}
                >
                  {b._id}
                  <span className="opacity-70">· {b.count}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
