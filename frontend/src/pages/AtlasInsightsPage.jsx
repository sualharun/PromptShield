import { useEffect, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'
import AtlasLiveBadge from '../components/AtlasLiveBadge.jsx'

/**
 * AtlasInsightsPage — single page that wires every Atlas-only endpoint
 * into one screen so judges can see the breadth of features in 30 seconds.
 *
 * Endpoints exercised:
 *   /api/v2/health                  — feature flags + corpus size
 *   /api/v2/risk-timeline           — $setWindowFields rolling avg
 *   /api/v2/aggregations/repos      — group_by aggregation
 *   /api/v2/aggregations/llm-targets — exploded array facet
 *   /api/v2/aggregations/top-cwes   — unwound finding facet
 *   /api/v2/search/facets           — $searchMeta (severity + CWE)
 *   /api/v2/benchmark/runs          — model registry / eval history
 *   /api/v2/models                  — GridFS-stored model artifacts
 *
 * Includes an Atlas Charts iframe stub (commented for the user to fill in
 * the embed URL after they create the chart in cloud.mongodb.com).
 */
const TOOLTIP_STYLE = {
  border: '1px solid #e0e0e0',
  background: '#ffffff',
  fontSize: 12,
  fontFamily: 'IBM Plex Sans, sans-serif',
  borderRadius: 0,
  padding: '8px 10px',
}

function StatTile({ label, value, hint, accent }) {
  return (
    <div className="border border-carbon-border bg-white px-4 py-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="text-[10px] font-medium uppercase tracking-[0.1em] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {label}
      </div>
      <div
        className="mt-1 font-light text-2xl tabular-nums"
        style={{ color: accent || 'var(--carbon-text)' }}
      >
        {value}
      </div>
      {hint && (
        <div className="mt-0.5 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          {hint}
        </div>
      )}
    </div>
  )
}

function Section({ title, subtitle, children }) {
  return (
    <section className="mt-6 border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="flex items-center justify-between border-b border-carbon-border px-4 py-2 dark:border-ibm-gray-80">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          {title}
        </h2>
        {subtitle && (
          <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            {subtitle}
          </span>
        )}
      </div>
      <div className="p-4">{children}</div>
    </section>
  )
}

async function safeFetch(url) {
  try {
    const r = await fetchWithTimeout(url)
    if (!r.ok) return null
    return await r.json()
  } catch {
    return null
  }
}

export default function AtlasInsightsPage() {
  const [health, setHealth] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [trendDelta, setTrendDelta] = useState(0)
  const [repos, setRepos] = useState([])
  const [llmTargets, setLlmTargets] = useState([])
  const [topCwes, setTopCwes] = useState([])
  const [facets, setFacets] = useState(null)
  const [benchRuns, setBenchRuns] = useState([])
  const [models, setModels] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([
      safeFetch('/api/v2/health'),
      safeFetch('/api/v2/risk-timeline?source=github&days=30'),
      safeFetch('/api/v2/aggregations/repos?source=github&limit=8'),
      safeFetch('/api/v2/aggregations/llm-targets'),
      safeFetch('/api/v2/aggregations/top-cwes?days=30&limit=8'),
      safeFetch('/api/v2/search/facets'),
      safeFetch('/api/v2/benchmark/runs?limit=10'),
      safeFetch('/api/v2/models'),
    ])
      .then(([h, tl, rp, lt, cw, fc, br, md]) => {
        if (cancelled) return
        setHealth(h)
        setTimeline(tl?.points || [])
        setTrendDelta(tl?.trend_delta ?? 0)
        setRepos(rp || [])
        setLlmTargets(lt || [])
        setTopCwes(cw || [])
        setFacets(fc || null)
        setBenchRuns(br || [])
        setModels(md?.models || [])
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const features = health?.features || {}
  const corpusSize = health?.corpus_size ?? 0
  const sev = facets?.severityFacet?.buckets || []
  const cwe = facets?.cweFacet?.buckets || []
  const latestBench = benchRuns[0]

  // OPTIONAL: Paste an Atlas Charts embed URL here to replace the placeholder.
  // Get it from cloud.mongodb.com → Charts → your dashboard → Embed → "Embed
  // chart on a webpage." Filter to the same scans collection used here.
  const ATLAS_CHART_EMBED_URL =
    import.meta.env?.VITE_ATLAS_CHART_EMBED_URL || ''

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[#13aa52]">
            <span className="h-1.5 w-1.5 bg-[#13aa52]" />
            MongoDB Atlas · feature inventory
          </p>
          <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
            Atlas Insights
          </h1>
          <p className="mt-1 max-w-xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Every Atlas-only feature wired to a live endpoint, so you can see
            them all in one screen instead of clicking through tabs.
          </p>
        </div>
        <AtlasLiveBadge />
      </div>

      {loading && (
        <div className="border border-carbon-border bg-white px-4 py-6 text-sm text-carbon-text-tertiary dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-40">
          Querying Atlas…
        </div>
      )}

      {!loading && (
        <>
          {/* Feature flag tiles ─────────────────────────────────────────── */}
          <section className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
            <StatTile
              label="Vector Search"
              value={features.vector_search ? 'live' : 'mock'}
              accent={features.vector_search ? '#13aa52' : '#8d8d8d'}
              hint="$vectorSearch · cosine"
            />
            <StatTile
              label="Atlas Search"
              value={features.atlas_search ? 'live' : 'mock'}
              accent={features.atlas_search ? '#13aa52' : '#8d8d8d'}
              hint="$search · Lucene"
            />
            <StatTile
              label="$rankFusion"
              value={features.rank_fusion ? 'live' : 'mock'}
              accent={features.rank_fusion ? '#13aa52' : '#8d8d8d'}
              hint="hybrid (vector + text)"
            />
            <StatTile
              label="Change Streams"
              value={features.change_streams ? 'live' : 'idle'}
              accent={features.change_streams ? '#13aa52' : '#8d8d8d'}
              hint="WS push, no polling"
            />
            <StatTile
              label="Time-Series"
              value={features.time_series ? 'live' : 'fallback'}
              accent={features.time_series ? '#13aa52' : '#8d8d8d'}
              hint="$setWindowFields"
            />
            <StatTile
              label="Corpus size"
              value={corpusSize}
              hint="prompt_vectors docs"
            />
            <StatTile
              label="Models in registry"
              value={models.length}
              hint="GridFS · model_registry"
            />
            <StatTile
              label="Bench runs"
              value={benchRuns.length}
              hint="benchmark_runs collection"
            />
          </section>

          {/* Timeline + repos ────────────────────────────────────────────── */}
          <Section
            title="Risk timeline (Atlas time-series · $setWindowFields)"
            subtitle={`Δ vs window start: ${trendDelta >= 0 ? '+' : ''}${trendDelta}`}
          >
            {timeline.length === 0 ? (
              <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                No snapshots yet — kick off a few PR scans, then return here.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={timeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                  <XAxis dataKey="ts" tickFormatter={(t) => t.slice(5, 10)} fontSize={11} />
                  <YAxis fontSize={11} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Area
                    type="monotone"
                    dataKey="risk_score"
                    name="Risk"
                    stroke="#0f62fe"
                    fill="#0f62fe33"
                  />
                  <Area
                    type="monotone"
                    dataKey="rolling_7d_avg"
                    name="7-day rolling"
                    stroke="#13aa52"
                    fill="#13aa5222"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </Section>

          <div className="grid gap-px md:grid-cols-2">
            <Section
              title="Top repos by scan count (group_by aggregation)"
              subtitle="$group · $sort"
            >
              {repos.length === 0 ? (
                <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                  No repos yet.
                </p>
              ) : (
                <ul className="space-y-1 text-[12px]">
                  {repos.map((r) => (
                    <li
                      key={r.repo_full_name}
                      className="flex items-center justify-between gap-3"
                    >
                      <span className="truncate text-carbon-text dark:text-ibm-gray-10">
                        {r.repo_full_name}
                      </span>
                      <span className="font-mono text-carbon-text-secondary dark:text-ibm-gray-30">
                        {r.scan_count} scans · avg {r.avg_risk}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section title="LLM targets (array facet)" subtitle="$unwind · $group">
              {llmTargets.length === 0 ? (
                <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                  No targets recorded.
                </p>
              ) : (
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={llmTargets} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
                    <XAxis type="number" fontSize={11} />
                    <YAxis type="category" dataKey="target" width={80} fontSize={11} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#0f62fe" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Section>
          </div>

          <div className="grid gap-px md:grid-cols-2">
            <Section title="Top CWEs (last 30d)" subtitle="$unwind findings · $group">
              {topCwes.length === 0 ? (
                <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                  No CWEs in window.
                </p>
              ) : (
                <ul className="space-y-1 text-[12px]">
                  {topCwes.map((c) => (
                    <li
                      key={c.cwe}
                      className="flex items-center justify-between gap-3"
                    >
                      <span className="font-mono text-carbon-text dark:text-ibm-gray-10">
                        {c.cwe}
                      </span>
                      <span className="font-mono text-carbon-text-secondary dark:text-ibm-gray-30">
                        {c.count}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section title="Search facets" subtitle="$searchMeta">
              {sev.length === 0 && cwe.length === 0 ? (
                <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                  No facet data — index might still be warming up.
                </p>
              ) : (
                <div className="space-y-3">
                  <div>
                    <div className="mb-1 text-[10px] uppercase tracking-wider text-carbon-text-tertiary dark:text-ibm-gray-40">
                      severity
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {sev.map((b) => (
                        <span
                          key={b._id}
                          className="border border-carbon-border bg-carbon-layer px-2 py-0.5 font-mono text-[11px] text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30"
                        >
                          {b._id} · {b.count}
                        </span>
                      ))}
                    </div>
                  </div>
                  {cwe.length > 0 && (
                    <div>
                      <div className="mb-1 text-[10px] uppercase tracking-wider text-carbon-text-tertiary dark:text-ibm-gray-40">
                        top CWEs
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {cwe.slice(0, 8).map((b) => (
                          <span
                            key={b._id}
                            className="border border-carbon-border bg-carbon-layer px-2 py-0.5 font-mono text-[11px] text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30"
                          >
                            {b._id} · {b.count}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </Section>
          </div>

          {/* Benchmark runs ───────────────────────────────────────────── */}
          <Section
            title="Benchmark history (model registry)"
            subtitle="benchmark_runs · sorted by ts"
          >
            {benchRuns.length === 0 ? (
              <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                Run <code>python three_layer_benchmark.py</code> to populate.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-carbon-border dark:border-ibm-gray-80">
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">When</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">Layers</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">Acc</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">Prec</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">Rec</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">F1</th>
                      <th className="px-2 py-2 font-mono uppercase tracking-wider">N</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchRuns.map((b) => (
                      <tr
                        key={b.id}
                        className="border-b border-carbon-border/60 dark:border-ibm-gray-80/60"
                      >
                        <td className="px-2 py-2 text-carbon-text-secondary dark:text-ibm-gray-30">
                          {String(b.ts).slice(0, 16).replace('T', ' ')}
                        </td>
                        <td className="px-2 py-2 font-mono text-carbon-text-secondary dark:text-ibm-gray-30">
                          {(b.layers_enabled || []).join(', ') || '—'}
                        </td>
                        <td className="px-2 py-2 font-mono">{(b.accuracy * 100).toFixed(1)}%</td>
                        <td className="px-2 py-2 font-mono">{(b.precision * 100).toFixed(1)}%</td>
                        <td className="px-2 py-2 font-mono">{(b.recall * 100).toFixed(1)}%</td>
                        <td className="px-2 py-2 font-mono">{(b.f1 * 100).toFixed(1)}%</td>
                        <td className="px-2 py-2 font-mono">{b.sample_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {latestBench && (
                  <p className="mt-2 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                    Latest run: F1 {(latestBench.f1 * 100).toFixed(1)}% on{' '}
                    {latestBench.sample_count} samples.
                  </p>
                )}
              </div>
            )}
          </Section>

          {/* Model registry (GridFS) ──────────────────────────────────── */}
          <Section
            title="Model registry (GridFS)"
            subtitle="bucket: model_registry"
          >
            {models.length === 0 ? (
              <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                No model artifacts uploaded yet. POST to{' '}
                <code>/api/v2/models/bootstrap</code> to backfill the
                ml_classifier.
              </p>
            ) : (
              <ul className="space-y-2 text-[12px]">
                {models.map((m) => (
                  <li
                    key={m.id}
                    className="border border-carbon-border bg-carbon-layer p-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono text-carbon-text dark:text-ibm-gray-10">
                        {m.name}
                      </span>
                      <span className="font-mono text-carbon-text-secondary dark:text-ibm-gray-30">
                        {Math.round(m.size_bytes / 1024)} KB
                      </span>
                    </div>
                    <div className="mt-0.5 flex justify-between gap-3 font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                      <span>sha256: {m.sha256?.slice(0, 16)}…</span>
                      <span>{String(m.uploaded_at).slice(0, 19).replace('T', ' ')}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          {/* Atlas Charts embed stub ──────────────────────────────────── */}
          <Section
            title="Atlas Charts embed"
            subtitle={ATLAS_CHART_EMBED_URL ? 'live iframe' : 'placeholder · set VITE_ATLAS_CHART_EMBED_URL'}
          >
            {ATLAS_CHART_EMBED_URL ? (
              <iframe
                title="Atlas Chart"
                style={{ background: '#fff', border: 'none', width: '100%', height: 420 }}
                src={ATLAS_CHART_EMBED_URL}
              />
            ) : (
              <div className="border border-dashed border-carbon-border bg-carbon-layer px-4 py-8 text-center text-[12px] leading-relaxed text-carbon-text-tertiary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-40">
                <p className="font-mono text-[11px] uppercase tracking-wider text-[#13aa52]">
                  ◆ Atlas Charts iframe slot
                </p>
                <p className="mt-2">
                  In <code>cloud.mongodb.com</code> → Charts, build a chart
                  against the <code>scans</code> or <code>risk_snapshots</code>{' '}
                  collection, click <em>Embed</em>, copy the iframe URL, then set{' '}
                  <code>VITE_ATLAS_CHART_EMBED_URL</code> in
                  <code> frontend/.env</code> and rebuild.
                </p>
                <p className="mt-2 text-[11px]">
                  Recommended chart: stacked-area of{' '}
                  <code>risk_snapshots.risk_score</code> by{' '}
                  <code>meta.source</code>, last 30 days.
                </p>
              </div>
            )}
          </Section>
        </>
      )}
    </div>
  )
}
