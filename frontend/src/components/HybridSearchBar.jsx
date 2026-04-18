import { useEffect, useRef, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

/**
 * HybridSearchBar — drives the dashboard's smart search bar.
 *
 * Type-ahead hits /api/v2/search/autocomplete (Atlas Search autocomplete
 * tokenizer); pressing Enter or clicking a suggestion fires
 * /api/v2/search/hybrid (the $rankFusion endpoint that merges $vectorSearch
 * + $search) using the current vector/text weight sliders.
 *
 * The "tune weights" disclosure lets a judge slide between
 * pure-semantic and pure-lexical at demo time, with the chosen weights
 * forwarded to the backend so they're reflected in the fusion_score field.
 *
 * Renders nothing fancy when Atlas isn't configured — both endpoints have
 * regex/in-process fallbacks on the server, so the bar still works.
 */
export default function HybridSearchBar({ onResults, source = null }) {
  const [q, setQ] = useState('')
  const [suggestions, setSuggestions] = useState([])
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [showWeights, setShowWeights] = useState(false)
  const [vectorWeight, setVectorWeight] = useState(1.0)
  const [textWeight, setTextWeight] = useState(1.0)
  const debounceRef = useRef(null)

  useEffect(() => {
    clearTimeout(debounceRef.current)
    if (!q.trim()) {
      setSuggestions([])
      setOpen(false)
      return
    }
    debounceRef.current = setTimeout(async () => {
      try {
        const r = await fetchWithTimeout(
          `/api/v2/search/autocomplete?prefix=${encodeURIComponent(q)}`,
        )
        if (!r.ok) return
        const data = await r.json()
        setSuggestions(data.suggestions || [])
        setOpen((data.suggestions || []).length > 0)
      } catch {
        /* ignore */
      }
    }, 180)
    return () => clearTimeout(debounceRef.current)
  }, [q])

  async function runSearch(query) {
    if (!query.trim()) return
    setLoading(true)
    setOpen(false)
    try {
      const r = await fetchWithTimeout('/api/v2/search/hybrid', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          q: query,
          k: 20,
          source,
          vector_weight: vectorWeight,
          text_weight: textWeight,
        }),
      })
      const data = await r.json()
      onResults?.({
        query,
        results: data.results || [],
        count: data.count || 0,
        weights: { vector: vectorWeight, text: textWeight },
      })
    } catch (e) {
      onResults?.({ query, results: [], count: 0, error: String(e) })
    } finally {
      setLoading(false)
    }
  }

  const vectorPct = Math.round((vectorWeight / (vectorWeight + textWeight)) * 100)
  const textPct = 100 - vectorPct

  return (
    <div className="relative w-full max-w-xl">
      <div className="flex items-center border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <span
          aria-hidden
          className="px-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#13aa52]"
          title="Atlas Hybrid Search ($rankFusion = $vectorSearch + $search)"
        >
          ◆ Atlas
        </span>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runSearch(q)}
          onFocus={() => suggestions.length > 0 && setOpen(true)}
          placeholder="Hybrid search · semantic + lexical (try: 'leak api credentials')"
          className="w-full bg-transparent px-2 py-2 text-sm text-carbon-text outline-none placeholder:text-carbon-text-tertiary dark:text-ibm-gray-10 dark:placeholder:text-ibm-gray-50"
        />
        <button
          type="button"
          onClick={() => setShowWeights((s) => !s)}
          title="Tune $rankFusion weights (vector vs text)"
          className="border-l border-carbon-border px-2 py-2 font-mono text-[10px] uppercase tracking-wider text-carbon-text-secondary transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
        >
          {vectorPct}/{textPct}
        </button>
        <button
          type="button"
          onClick={() => runSearch(q)}
          disabled={!q.trim() || loading}
          className="border-l border-carbon-border bg-white px-3 py-2 text-xs font-medium text-carbon-text-secondary transition-colors hover:bg-carbon-layer disabled:cursor-not-allowed disabled:opacity-60 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
        >
          {loading ? 'Searching…' : 'Search'}
        </button>
      </div>

      {showWeights && (
        <div className="mt-1 border border-carbon-border bg-white px-3 py-2 text-[11px] dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="mb-1 flex items-center justify-between text-carbon-text-secondary dark:text-ibm-gray-30">
            <span>
              <span className="font-semibold text-[#13aa52]">vector</span> weight
            </span>
            <span className="font-mono">{vectorWeight.toFixed(2)}</span>
          </div>
          <input
            aria-label="Vector weight"
            type="range"
            min="0"
            max="2"
            step="0.05"
            value={vectorWeight}
            onChange={(e) => setVectorWeight(parseFloat(e.target.value))}
            className="w-full accent-[#13aa52]"
          />
          <div className="mb-1 mt-2 flex items-center justify-between text-carbon-text-secondary dark:text-ibm-gray-30">
            <span>
              <span className="font-semibold text-ibm-blue-70">text</span> weight
            </span>
            <span className="font-mono">{textWeight.toFixed(2)}</span>
          </div>
          <input
            aria-label="Text weight"
            type="range"
            min="0"
            max="2"
            step="0.05"
            value={textWeight}
            onChange={(e) => setTextWeight(parseFloat(e.target.value))}
            className="w-full accent-ibm-blue-60"
          />
          <p className="mt-2 leading-relaxed text-carbon-text-tertiary dark:text-ibm-gray-40">
            Forwarded to <code>$rankFusion.combination.weights</code>. 0 ⇒
            disable that pipeline; equal weights ⇒ classic RRF.
          </p>
        </div>
      )}

      {open && (
        <ul
          role="listbox"
          className="absolute left-0 right-0 z-30 mt-1 max-h-64 overflow-auto border border-carbon-border bg-white shadow-md dark:border-ibm-gray-80 dark:bg-ibm-gray-90"
        >
          {suggestions.map((s) => (
            <li
              key={s}
              role="option"
              tabIndex={0}
              onClick={() => {
                setQ(s)
                runSearch(s)
              }}
              onKeyDown={(e) => e.key === 'Enter' && runSearch(s)}
              className="cursor-pointer px-3 py-2 text-sm text-carbon-text hover:bg-carbon-layer dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
            >
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
