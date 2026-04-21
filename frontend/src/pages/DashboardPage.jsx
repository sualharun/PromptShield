import { useEffect, useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import PRScanRow from '../components/PRScanRow.jsx'
import RiskGauge from '../components/RiskGauge.jsx'
import AtlasLiveBadge from '../components/AtlasLiveBadge.jsx'
import HybridSearchBar from '../components/HybridSearchBar.jsx'
import SearchHighlights from '../components/SearchHighlights.jsx'
import SearchFacets from '../components/SearchFacets.jsx'
import { asNetworkErrorMessage, fetchWithTimeout } from '../lib/fetchWithTimeout.js'

const INSTALL_URL =
  import.meta.env?.VITE_GITHUB_APP_INSTALL_URL || '#'

const TOOLTIP_STYLE = {
  border: '1px solid #e0e0e0',
  background: '#ffffff',
  fontSize: 12,
  fontFamily: 'IBM Plex Sans, sans-serif',
  borderRadius: 0,
  padding: '8px 10px',
}

const SEVERITY_COLORS = {
  critical: '#da1e28',
  high: '#ff832b',
  medium: '#f1c21b',
  low: '#0f62fe',
}

function avgRiskColor(v) {
  if (v <= 30) return '#198038'
  if (v <= 60) return '#8a6800'
  if (v <= 85) return '#b8470c'
  return '#a2191f'
}

function Tile({ label, value, accent, hint, compact }) {
  return (
    <div className={`bg-white dark:bg-ibm-gray-90 ${compact ? 'px-4 py-3' : 'px-5 py-5'}`}>
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {label}
      </div>
      <div
        className={`mt-1 font-light tabular-nums ${compact ? 'text-2xl' : 'text-3xl'}`}
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

function StackedSeverityBar({ severity }) {
  const total =
    (severity?.critical || 0) +
    (severity?.high || 0) +
    (severity?.medium || 0) +
    (severity?.low || 0)
  if (!total) {
    return (
      <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
        No findings to bucket yet.
      </p>
    )
  }
  const segments = [
    { key: 'critical', label: 'Critical', value: severity.critical || 0, color: SEVERITY_COLORS.critical },
    { key: 'high', label: 'High', value: severity.high || 0, color: SEVERITY_COLORS.high },
    { key: 'medium', label: 'Medium', value: severity.medium || 0, color: SEVERITY_COLORS.medium },
    { key: 'low', label: 'Low', value: severity.low || 0, color: SEVERITY_COLORS.low },
  ]
  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden border border-carbon-border dark:border-ibm-gray-80">
        {segments.map((s) => {
          const pct = (s.value / total) * 100
          if (!pct) return null
          return (
            <div
              key={s.key}
              style={{ width: `${pct}%`, background: s.color }}
              title={`${s.label}: ${s.value} (${pct.toFixed(1)}%)`}
            />
          )
        })}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-4">
        {segments.map((s) => (
          <div key={s.key} className="flex items-center gap-2 text-[12px]">
            <span className="h-2 w-2" style={{ background: s.color }} />
            <span className="text-carbon-text-secondary dark:text-ibm-gray-30">
              {s.label}
            </span>
            <span className="ml-auto font-mono tabular-nums text-carbon-text dark:text-ibm-gray-10">
              {s.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TrendDelta({ daily }) {
  const delta = useMemo(() => {
    if (!daily || daily.length < 14) return null
    const last = daily.slice(-7)
    const prev = daily.slice(-14, -7)
    const avg = (arr) => {
      const withScans = arr.filter((d) => d.scan_count > 0)
      if (!withScans.length) return null
      return withScans.reduce((s, d) => s + d.avg_risk, 0) / withScans.length
    }
    const a = avg(last)
    const b = avg(prev)
    if (a == null || b == null) return null
    return { diff: a - b, current: a }
  }, [daily])

  if (!delta) {
    return (
      <span className="text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary dark:text-ibm-gray-40">
        Needs 14 days of history
      </span>
    )
  }
  const improving = delta.diff < 0
  const color = improving ? '#198038' : delta.diff > 0 ? '#a2191f' : '#6f6f6f'
  const arrow = improving ? '▼' : delta.diff > 0 ? '▲' : '—'
  return (
    <span
      className="inline-flex items-center gap-1 text-[12px] font-medium tabular-nums"
      style={{ color }}
    >
      <span>{arrow}</span>
      <span>{Math.abs(delta.diff).toFixed(1)} pts</span>
      <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
        vs prior 7 days
      </span>
    </span>
  )
}

function shortDay(d) {
  try {
    const dt = new Date(d)
    return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  } catch {
    return d
  }
}

function RiskTrendPanel({ daily, atlasTimeline }) {
  const hasV = daily?.length > 0
  const hasA = atlasTimeline?.length > 0
  const [tab, setTab] = useState(hasV ? 'velocity' : 'atlas')

  useEffect(() => {
    if (hasV && !hasA) setTab('velocity')
    else if (!hasV && hasA) setTab('atlas')
  }, [hasV, hasA])

  if (!hasV && !hasA) return null

  const both = hasV && hasA
  const showAtlas = (both && tab === 'atlas') || (!both && hasA)
  const tabBtn =
    'rounded px-3 py-1.5 text-[12px] font-medium transition-colors focus-visible:outline focus-visible:ring-2 focus-visible:ring-ibm-blue-60'
  const tabActive = 'bg-ibm-blue-60 text-white'
  const tabIdle =
    'text-carbon-text-secondary hover:bg-carbon-layer dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-100'

  return (
    <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Risk trend
          </h2>
          <p className="mt-0.5 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            {both && tab === 'velocity' && 'Average risk from PR scans (last ~14 days with activity)'}
            {both && tab === 'atlas' && 'Atlas time-series with 7-day rolling average (30 days)'}
            {!both && hasV && 'Average risk from PR scans (recent daily buckets)'}
            {!both && hasA && 'Atlas time-series with 7-day rolling average'}
          </p>
        </div>
        {both && (
          <div
            className="flex rounded border border-carbon-border p-0.5 dark:border-ibm-gray-80"
            role="tablist"
            aria-label="Trend data source"
          >
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'velocity'}
              className={`${tabBtn} ${tab === 'velocity' ? tabActive : tabIdle}`}
              onClick={() => setTab('velocity')}
            >
              PR scans (14d)
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'atlas'}
              className={`${tabBtn} ${tab === 'atlas' ? tabActive : tabIdle}`}
              onClick={() => setTab('atlas')}
            >
              Atlas (30d)
            </button>
          </div>
        )}
      </div>
      <div className="h-60 w-full">
        <ResponsiveContainer width="100%" height="100%">
          {showAtlas ? (
            <AreaChart
              data={atlasTimeline.map((p) => ({
                ...p,
                label: shortDay(p.ts),
              }))}
              margin={{ top: 8, right: 16, left: 0, bottom: 8 }}
            >
              <defs>
                <linearGradient id="atlasRiskFillDash" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#13aa52" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#13aa52" stopOpacity={0.04} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#e0e0e0" vertical={false} />
              <XAxis
                dataKey="label"
                stroke="#6f6f6f"
                tickLine={false}
                axisLine={{ stroke: '#c6c6c6' }}
                tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
              />
              <YAxis
                domain={[0, 100]}
                stroke="#6f6f6f"
                tickLine={false}
                axisLine={false}
                tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area
                type="monotone"
                dataKey="risk_score"
                stroke="#13aa52"
                strokeWidth={1.7}
                fill="url(#atlasRiskFillDash)"
                name="Risk"
                animationDuration={700}
              />
              <Area
                type="monotone"
                dataKey="rolling_7d_avg"
                stroke="#0f62fe"
                strokeWidth={2.2}
                fillOpacity={0}
                name="Rolling avg"
                animationDuration={700}
              />
            </AreaChart>
          ) : (
            <AreaChart
              data={daily.map((p) => ({
                ...p,
                label: shortDay(p.date),
              }))}
              margin={{ top: 8, right: 16, left: 0, bottom: 8 }}
            >
              <defs>
                <linearGradient id="riskFillDash" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#0f62fe" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#0f62fe" stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#e0e0e0" vertical={false} />
              <XAxis
                dataKey="label"
                stroke="#6f6f6f"
                tickLine={false}
                axisLine={{ stroke: '#c6c6c6' }}
                tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
              />
              <YAxis
                domain={[0, 100]}
                stroke="#6f6f6f"
                tickLine={false}
                axisLine={false}
                tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area
                type="monotone"
                dataKey="avg_risk"
                stroke="#0f62fe"
                strokeWidth={2}
                fill="url(#riskFillDash)"
                name="Avg risk"
                animationDuration={700}
              />
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
    </section>
  )
}

export default function DashboardPage({ onSelectScan }) {
  const [data, setData] = useState(null)
  const [atlasTimeline, setAtlasTimeline] = useState([])
  const [hybrid, setHybrid] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  const loadDashboard = () => {
    setLoading(true)
    setError(null)
    return Promise.all([
      fetchWithTimeout('/api/dashboard/github'),
      fetchWithTimeout('/api/v2/risk-timeline?source=github&days=30').catch(() => null),
    ])
      .then(([dashboardRes, atlasTimelineRes]) => {
        if (!dashboardRes?.ok) {
          throw new Error(`Dashboard load failed (${dashboardRes?.status ?? 'n/a'})`)
        }
        return Promise.all([
          dashboardRes.json(),
          atlasTimelineRes?.ok ? atlasTimelineRes.json() : Promise.resolve(null),
        ])
      })
      .then(([dashboardData, timelineData]) => {
        setData(dashboardData)
        setAtlasTimeline(timelineData?.points || [])
      })
      .catch((e) => {
        setError(asNetworkErrorMessage(e, 'Dashboard load failed'))
      })
      .finally(() => {
        setLoading(false)
      })
  }

  useEffect(() => {
    loadDashboard()
  }, [refreshKey])

  // Auto-sync from GitHub when dashboard loads empty
  const [autoSynced, setAutoSynced] = useState(false)
  useEffect(() => {
    if (!loading && data && data.total_pr_scans === 0 && !autoSynced && !syncing) {
      setAutoSynced(true)
      syncFromGitHub()
    }
  }, [loading, data, autoSynced, syncing])

  const syncFromGitHub = async () => {
    setSyncing(true)
    setSyncResult(null)
    try {
      const r = await fetchWithTimeout('/api/github/sync', { method: 'POST' }, 60000)
      if (!r.ok) {
        const detail = await r.json().catch(() => ({}))
        throw new Error(detail.detail || `Sync failed (${r.status})`)
      }
      const result = await r.json()
      setSyncResult(result)
      if (result.synced > 0) {
        setRefreshKey((k) => k + 1)
      }
    } catch (e) {
      setSyncResult({ error: e.message || 'Sync failed' })
    } finally {
      setSyncing(false)
    }
  }

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="h-9 w-56 animate-pulse rounded bg-[#e8e6e0]" />
        <div className="mt-2 h-4 max-w-md animate-pulse rounded bg-[#e8e6e0]" />
        <div className="mt-8 grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map((k) => (
            <div
              key={k}
              className="h-36 animate-pulse rounded border border-[#dcd9cf] bg-white"
            />
          ))}
        </div>
        <p className="mt-6 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Loading GitHub activity…
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div
          role="alert"
          className="border-l-4 border-ibm-red-60 border-y border-r border-carbon-border bg-[#fff1f1] px-4 py-3 text-sm text-ibm-red-70 dark:border-ibm-gray-80 dark:bg-ibm-red-70/20 dark:text-ibm-red-50"
        >
          {error}
        </div>
      </div>
    )
  }

  const empty = !data || data.total_pr_scans === 0
  const severity = data?.severity_totals || { critical: 0, high: 0, medium: 0, low: 0 }
  const avgRisk = data?.avg_risk ?? 0

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-light text-3xl leading-tight text-carbon-text md:text-4xl dark:text-ibm-gray-10">
            Security posture
          </h1>
          <p className="mt-2 max-w-2xl text-[13px] leading-relaxed text-carbon-text-tertiary dark:text-ibm-gray-40">
            PR scans from the GitHub App and <span className="font-medium text-carbon-text-secondary dark:text-ibm-gray-30">Sync PRs</span>. Use search to jump to scans; charts below summarize org-wide risk.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <AtlasLiveBadge source="github" />
          {!empty && (
            <a
              href="/api/dashboard/github/export.csv"
              className="inline-flex items-center gap-2 border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
            >
              Export CSV
              <span className="text-xs">↓</span>
            </a>
          )}
          <button
            onClick={syncFromGitHub}
            disabled={syncing}
            className="inline-flex items-center gap-2 border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer disabled:opacity-60 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            {syncing ? 'Syncing…' : 'Sync PRs'}
            <span className="text-xs">{syncing ? '⟳' : '↻'}</span>
          </button>
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70"
          >
            Connect a repo
            <span className="text-base leading-none">→</span>
          </a>
        </div>
      </div>

      {syncResult && (
        <div
          className={`mb-4 border px-4 py-3 text-sm ${
            syncResult.error
              ? 'border-ibm-red-60/40 bg-[#fff1ec] text-[#8f3c2d]'
              : 'border-ibm-green-50/40 bg-[#defbe6] text-[#0e6027]'
          }`}
        >
          {syncResult.error
            ? `Sync failed: ${syncResult.error}`
            : `Synced ${syncResult.synced} PR scan(s) from GitHub.`}
          <button
            onClick={() => setSyncResult(null)}
            className="ml-3 text-xs underline"
          >
            dismiss
          </button>
        </div>
      )}

      <section className="mb-6 border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Search scans
        </h2>
        <HybridSearchBar
          source="github"
          onResults={({ query, results, count, weights, error: searchError }) => {
            if (!query) return
            setHybrid({
              query,
              results: results || [],
              count: count || 0,
              weights: weights || null,
              error: searchError || null,
              facetFilter: {},
            })
          }}
        />
        <div className="mt-4 border-t border-carbon-border pt-4 dark:border-ibm-gray-80">
          <SearchFacets
            query={hybrid?.query || null}
            active={hybrid?.facetFilter || {}}
            onSelect={({ key, value }) => {
              setHybrid((h) => {
                if (!h) return h
                const cur = h.facetFilter || {}
                const next =
                  cur[key] === value
                    ? { ...cur, [key]: undefined }
                    : { ...cur, [key]: value }
                return { ...h, facetFilter: next }
              })
            }}
          />
        </div>
      </section>

      <details className="mb-6 border border-carbon-border bg-[#fbfaf7] px-4 py-2 text-[12px] text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
        <summary className="cursor-pointer select-none font-medium text-carbon-text dark:text-ibm-gray-10">
          MongoDB Atlas in this dashboard
        </summary>
        <p className="mt-2 text-[12px] leading-relaxed text-carbon-text-tertiary dark:text-ibm-gray-40">
          Hybrid search combines vector + full-text with rank fusion; live updates use change streams;
          trend can include Atlas time-series. Requires a configured Atlas cluster and indexes.
        </p>
      </details>

      {hybrid && (
        <section className="mb-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Hybrid search results
            </h2>
            <div className="flex items-center gap-2 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              <span>
                "{hybrid.query}" · {hybrid.count} result{hybrid.count === 1 ? '' : 's'}
              </span>
              {hybrid.weights && (
                <span className="border border-carbon-border bg-carbon-layer px-1.5 py-0.5 font-mono text-[10px] dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
                  weights v{hybrid.weights.vector?.toFixed(2)} · t{hybrid.weights.text?.toFixed(2)}
                </span>
              )}
              {hybrid.facetFilter && Object.values(hybrid.facetFilter).some(Boolean) && (
                <button
                  type="button"
                  onClick={() => setHybrid((h) => h && { ...h, facetFilter: {} })}
                  className="border border-carbon-border bg-white px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-ibm-blue-70 hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-blue-30"
                >
                  clear filters
                </button>
              )}
            </div>
          </div>
          {hybrid.error ? (
            <p className="text-sm text-ibm-red-60">{hybrid.error}</p>
          ) : hybrid.results.length === 0 ? (
            <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
              No matching scans. Try broader terms like "credentials", "jailbreak", or "system prompt".
            </p>
          ) : (
            (() => {
              const ff = hybrid.facetFilter || {}
              const filtered = hybrid.results.filter((r) => {
                if (ff.severity) {
                  const sevs = (r.findings || []).map((f) =>
                    String(f.severity || '').toLowerCase(),
                  )
                  if (!sevs.includes(ff.severity)) return false
                }
                if (ff.cwe) {
                  const cwes = (r.findings || []).map((f) => f.cwe).filter(Boolean)
                  if (!cwes.includes(ff.cwe)) return false
                }
                return true
              })
              if (filtered.length === 0) {
                return (
                  <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                    All results filtered out. Click an active facet chip to clear it.
                  </p>
                )
              }
              return (
                <ul className="divide-y divide-carbon-border dark:divide-ibm-gray-80">
                  {filtered.slice(0, 10).map((r) => {
                    const fused =
                      typeof r.fusion_score === 'number'
                        ? r.fusion_score
                        : r.fusion_score?.value ?? null
                    return (
                      <li key={r.id} className="py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium text-carbon-text dark:text-ibm-gray-10">
                            {r.repo_full_name || r.source || 'web'}
                          </span>
                          {r.pr_number && (
                            <span className="font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                              #{r.pr_number}
                            </span>
                          )}
                          <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                            · {shortDay(r.created_at)}
                          </span>
                          <span className="ml-auto inline-flex items-center gap-2 font-mono text-[11px]">
                            {fused !== null && (
                              <span
                                title="$rankFusion combined score (vector + text via reciprocal rank)"
                                className="border border-[#13aa52] bg-[#13aa52]/10 px-1.5 py-0.5 uppercase tracking-wider text-[#13aa52]"
                              >
                                ◆ fusion {Number(fused).toFixed(3)}
                              </span>
                            )}
                            <span className="text-carbon-text-secondary dark:text-ibm-gray-30">
                              risk {Math.round(r.risk_score || 0)}
                            </span>
                            <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
                              · {r.total_count || 0} findings
                            </span>
                          </span>
                        </div>
                        {r.highlights && r.highlights.length > 0 && (
                          <div className="mt-2">
                            <SearchHighlights highlights={r.highlights} max={2} />
                          </div>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )
            })()
          )}
        </section>
      )}

      {empty ? (
        <section className="mt-8 border border-carbon-border bg-white px-8 py-12 text-center dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ibm-blue-70 dark:text-ibm-blue-40">
            No PR scans yet
          </p>
          <h2 className="mt-2 font-light text-2xl text-carbon-text dark:text-ibm-gray-10">
            Install the GitHub App to start auto-reviewing pull requests
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            PromptShield runs on every PR — posts inline comments on risky
            prompt code and a Check Run gate that can block merging when the
            risk score crosses the configured threshold.
          </p>
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="mt-5 inline-flex items-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70"
          >
            Install GitHub App
            <span className="text-base leading-none">→</span>
          </a>
        </section>
      ) : (
        <>
          <section className="border border-carbon-border bg-white dark:border-ibm-gray-80">
            <div className="grid gap-6 px-5 py-6 lg:grid-cols-[minmax(220px,280px),1fr] lg:items-start">
              <div className="flex flex-col items-center justify-center lg:items-start lg:justify-start">
                <RiskGauge score={Math.round(avgRisk)} size={176} />
                <p className="mt-3 max-w-[220px] text-center text-[11px] leading-snug text-carbon-text-tertiary lg:text-left dark:text-ibm-gray-40">
                  Org-wide average risk · {data.total_pr_scans} PR scan
                  {data.total_pr_scans === 1 ? '' : 's'}
                </p>
                <div className="mt-2">
                  <TrendDelta daily={data.daily_velocity} />
                </div>
              </div>
              <div className="grid gap-px bg-carbon-border sm:grid-cols-2 xl:grid-cols-3 dark:bg-ibm-gray-80">
                <Tile
                  compact
                  label="Total PR scans"
                  value={data.total_pr_scans ?? 0}
                  hint="Connected repos"
                />
                <Tile
                  compact
                  label={`Gate failures (≥${data.threshold ?? 70})`}
                  value={data.gate_failures ?? 0}
                  accent="#a2191f"
                  hint="Over threshold"
                />
                <Tile
                  compact
                  label="Repos covered"
                  value={data.repos_covered ?? 0}
                />
                <Tile
                  compact
                  label="Avg findings / PR"
                  value={
                    data.avg_findings_per_pr != null
                      ? data.avg_findings_per_pr.toFixed(2)
                      : '0.00'
                  }
                  accent="#8a3ffc"
                />
                <Tile
                  compact
                  label="Agent findings"
                  value={data.agent_findings_count ?? 0}
                  accent="#ff832b"
                  hint="Tool / output issues"
                />
                <Tile
                  compact
                  label="Defense gaps"
                  value={data.validation_gap_pct != null ? `${data.validation_gap_pct}%` : '0%'}
                  accent="#da1e28"
                  hint="Missing delimiters / refusal / label"
                />
              </div>
            </div>
          </section>

          <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Severity mix
              </h2>
              <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                {(severity.critical || 0) +
                  (severity.high || 0) +
                  (severity.medium || 0) +
                  (severity.low || 0)}{' '}
                findings total
              </span>
            </div>
            <StackedSeverityBar severity={severity} />
          </section>

          <RiskTrendPanel
            daily={data.daily_velocity || []}
            atlasTimeline={atlasTimeline || []}
          />

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <section className="border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Top vulnerability types
              </h2>
              {data.top_finding_types?.length > 0 ? (
                <div className="h-56 w-full min-w-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={data.top_finding_types}
                      margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
                    >
                      <CartesianGrid stroke="#e0e0e0" horizontal={false} />
                      <XAxis
                        type="number"
                        allowDecimals={false}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={{ stroke: '#c6c6c6' }}
                        tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="type"
                        width={148}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fontSize: 10, fontFamily: 'IBM Plex Sans, sans-serif' }}
                        tickFormatter={(t) => (t.startsWith('AGENT_') ? `◆ ${t}` : t)}
                      />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Bar dataKey="count" fill="#8a3ffc" animationDuration={700}>
                        {data.top_finding_types.map((entry) => (
                          <Cell
                            key={entry.type}
                            fill={entry.type.startsWith('AGENT_') ? '#ff832b' : '#8a3ffc'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                  No findings yet.
                </p>
              )}
            </section>

            {data.by_repo?.length > 0 && (
              <section className="border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
                <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                  Risk by repository
                </h2>
                <div className="h-56 w-full min-w-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={data.by_repo.map((r) => ({
                        name: r.repo_full_name,
                        avg_risk: r.avg_risk,
                        scan_count: r.scan_count,
                      }))}
                      margin={{ top: 8, right: 16, left: 8, bottom: 8 }}
                    >
                      <CartesianGrid stroke="#e0e0e0" horizontal={false} />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={{ stroke: '#c6c6c6' }}
                        tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans, sans-serif' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={148}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fontSize: 10, fontFamily: 'IBM Plex Sans, sans-serif' }}
                      />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Bar dataKey="avg_risk" animationDuration={700}>
                        {data.by_repo.map((r, i) => (
                          <Cell key={i} fill={avgRiskColor(r.avg_risk)} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </section>
            )}
          </div>

          <section className="mt-6">
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Recent pull requests
            </h2>
            <div className="overflow-x-auto rounded border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
              <table className="w-full min-w-[720px] text-left">
                <thead className="sticky top-0 z-10 border-b border-carbon-border bg-[#f3f1ea] shadow-sm dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
                  <tr>
                    {[
                      'Repository',
                      'PR',
                      'Commit',
                      'Score',
                      'State',
                      'Time',
                      '',
                    ].map((h, i) => (
                      <th
                        key={i}
                        className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.recent.map((s) => (
                    <PRScanRow
                      key={s.id}
                      scan={s}
                      threshold={data.threshold}
                      onSelect={onSelectScan}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
