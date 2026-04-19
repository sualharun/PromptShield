import { useEffect, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

/**
 * SimilarScansPanel — calls /api/v2/scans/{id}/similar (Atlas Vector Search
 * over the labeled prompt corpus) and renders the top-k semantic neighbors
 * for the current scan.
 *
 * If the v2 endpoint isn't available (Atlas not configured), shows a friendly
 * "feature requires MongoDB Atlas" placeholder rather than failing loudly.
 */
export default function SimilarScansPanel({ scanId }) {
  const [matches, setMatches] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!scanId) return
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchWithTimeout(`/api/v2/scans/${scanId}/similar?k=5`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`atlas v2 unavailable (${r.status})`)
        return r.json()
      })
      .then((data) => {
        if (cancelled) return
        setMatches(data.matches || [])
      })
      .catch((e) => {
        if (cancelled) return
        setError(String(e.message || e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  function colorForScore(s) {
    const v = Math.round((s || 0) * 100)
    if (v >= 90) return '#a2191f'
    if (v >= 75) return '#b8470c'
    if (v >= 60) return '#8a6800'
    return '#198038'
  }

  return (
    <div className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          ◆ Atlas Vector Search · similar past scans
        </h3>
        <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          $vectorSearch · cosine
        </span>
      </div>

      {loading && (
        <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Querying Atlas Vector Search…
        </p>
      )}

      {error && !loading && (
        <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Semantic neighbor lookup unavailable ({error}). Connect to MongoDB
          Atlas to enable this view.
        </p>
      )}

      {!loading && !error && matches && matches.length === 0 && (
        <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          No semantically similar prompts found in the corpus.
        </p>
      )}

      {!loading && !error && matches && matches.length > 0 && (
        <ol className="space-y-2">
          {matches.map((m, idx) => (
            <li
              key={`${m.text}-${idx}`}
              className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
            >
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <span className="font-mono text-[10px] uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30">
                  #{idx + 1}
                </span>
                {m.category && (
                  <span className="border border-carbon-border bg-white px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30">
                    {m.category}
                  </span>
                )}
                {m.expected && (
                  <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                    expected: {m.expected}
                  </span>
                )}
                <span
                  className="ml-auto font-mono text-[11px] font-semibold"
                  style={{ color: colorForScore(m.score) }}
                  title="Cosine similarity (higher = closer match)"
                >
                  {Math.round((m.score || 0) * 100)}%
                </span>
              </div>
              <p className="text-[12px] leading-relaxed text-carbon-text dark:text-ibm-gray-10">
                "{m.text}"
              </p>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
