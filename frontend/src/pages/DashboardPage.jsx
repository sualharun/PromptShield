import { useEffect, useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
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

const INSTALL_URL = import.meta.env?.VITE_GITHUB_APP_INSTALL_URL || '#'

const TOOLTIP_STYLE = {
  border: '1px solid rgba(129, 159, 224, 0.16)',
  background: 'rgba(0, 0, 0, 0.98)',
  color: '#f5f8ff',
  fontSize: 12,
  fontFamily: 'IBM Plex Mono, monospace',
  borderRadius: 4,
  padding: '8px 10px',
}

const SEVERITY_COLORS = {
  critical: '#ff5b73',
  high: '#ff9b52',
  medium: '#ffd86e',
  low: '#5ea8ff',
}

function avgRiskColor(v) {
  if (v <= 30) return '#5ec8ff'
  if (v <= 60) return '#ffd86e'
  if (v <= 85) return '#ff9b52'
  return '#ff5b73'
}

function Tile({ label, value, accent, hint }) {
  return (
    <div className="terminal-soft px-5 py-5">
      <div className="terminal-label text-[10px] font-medium">
        {label}
      </div>
      <div
        className="terminal-mono mt-3 text-[2.4rem] font-light leading-none tabular-nums"
        style={{ color: accent || '#f5f8ff' }}
      >
        {value}
      </div>
      {hint && <div className="mt-2 text-[12px] leading-[1.5] text-[#9bb2d6]">{hint}</div>}
    </div>
  )
}

function FrostSection({ children, className = '' }) {
  return <section className={`terminal-panel p-5 ${className}`}>{children}</section>
}

function DashboardHeading({ kicker, title, body }) {
  return (
    <div>
      <p className="terminal-label text-[10px] font-semibold">{kicker}</p>
      <h1 className="terminal-mono mt-3 text-[clamp(2rem,3vw,3rem)] font-semibold leading-[1.02] tracking-[-0.04em] text-white">
        {title}
      </h1>
      <p className="mt-4 max-w-2xl text-[14px] leading-[1.7] text-[#a9c1e6]">
        {body}
      </p>
    </div>
  )
}

function SectionHeading({ title, meta }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="terminal-label text-[10px] font-semibold">{title}</h2>
      {meta ? <span className="text-[12px] text-[#8da7cd]">{meta}</span> : null}
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
    return <p className="text-sm text-[#8da7cd]">No findings to bucket yet.</p>
  }
  const segments = [
    { key: 'critical', label: 'Critical', value: severity.critical || 0, color: SEVERITY_COLORS.critical },
    { key: 'high', label: 'High', value: severity.high || 0, color: SEVERITY_COLORS.high },
    { key: 'medium', label: 'Medium', value: severity.medium || 0, color: SEVERITY_COLORS.medium },
    { key: 'low', label: 'Low', value: severity.low || 0, color: SEVERITY_COLORS.low },
  ]
  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden border border-white/10">
        {segments.map((segment) => {
          const pct = (segment.value / total) * 100
          if (!pct) return null
          return (
            <div
              key={segment.key}
              style={{ width: `${pct}%`, background: segment.color }}
              title={`${segment.label}: ${segment.value} (${pct.toFixed(1)}%)`}
            />
          )
        })}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-4">
        {segments.map((segment) => (
          <div key={segment.key} className="flex items-center gap-2 text-[12px]">
            <span className="h-2 w-2 rounded-full" style={{ background: segment.color }} />
            <span className="text-[#a8bfdf]">{segment.label}</span>
            <span className="terminal-mono ml-auto tabular-nums text-[#eef5ff]">
              {segment.value}
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
    return { diff: a - b }
  }, [daily])

  if (!delta) {
    return (
      <span className="text-[11px] uppercase tracking-[0.1em] text-[#8da7cd]">
        Needs 14 days of history
      </span>
    )
  }

  const improving = delta.diff < 0
  const color = improving ? '#5ec8ff' : delta.diff > 0 ? '#ff7d8f' : '#8da7cd'
  const arrow = improving ? '▼' : delta.diff > 0 ? '▲' : '—'

  return (
    <span className="inline-flex items-center gap-1 text-[12px] font-medium tabular-nums" style={{ color }}>
      <span>{arrow}</span>
      <span>{Math.abs(delta.diff).toFixed(1)} pts</span>
      <span className="text-[#8da7cd]">vs prior 7 days</span>
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

function RankedFindingTypes({ items = [] }) {
  if (!items.length) {
    return <p className="text-sm text-[#8da7cd]">No findings yet.</p>
  }

  const max = Math.max(...items.map((item) => item.count || 0), 1)

  return (
    <div className="space-y-3">
      {items.slice(0, 5).map((item) => (
        <div key={item.type} className="terminal-soft px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="text-[13px] text-[#eef5ff]">{item.type}</div>
            <div className="terminal-mono text-[13px] tabular-nums text-[#8fbcff]">{item.count}</div>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/6">
            <div
              className="h-full rounded-full bg-[#5ea8ff]"
              style={{ width: `${Math.max((item.count / max) * 100, 8)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

function RepoRiskList({ items = [] }) {
  if (!items.length) {
    return <p className="text-sm text-[#8da7cd]">No repository rollups yet.</p>
  }

  return (
    <div className="space-y-3">
      {items.slice(0, 5).map((repo) => (
        <div key={repo.repo_full_name} className="terminal-soft px-4 py-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-[#eef5ff]">{repo.repo_full_name}</div>
              <div className="mt-1 text-[12px] text-[#8da7cd]">
                {repo.scan_count} scan{repo.scan_count === 1 ? '' : 's'}
              </div>
            </div>
            <div
              className="terminal-mono text-[24px] leading-none tabular-nums"
              style={{ color: avgRiskColor(repo.avg_risk) }}
            >
              {Math.round(repo.avg_risk)}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function DashboardPage({ onSelectScan }) {
  const [data, setData] = useState(null)
  const [atlasTimeline, setAtlasTimeline] = useState([])
  const [hybrid, setHybrid] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([
      fetchWithTimeout('/api/dashboard/github'),
      fetchWithTimeout('/api/v2/risk-timeline?source=github&days=30').catch(() => null),
    ])
      .then(([dashboardRes, atlasTimelineRes]) => {
        if (cancelled) return
        if (!dashboardRes?.ok) {
          throw new Error(`Dashboard load failed (${dashboardRes?.status ?? 'n/a'})`)
        }
        return Promise.all([
          dashboardRes.json(),
          atlasTimelineRes?.ok ? atlasTimelineRes.json() : Promise.resolve(null),
        ])
      })
      .then((resolved) => {
        if (!resolved || cancelled) return
        const [dashboardData, timelineData] = resolved
        setData(dashboardData)
        setAtlasTimeline(timelineData?.points || [])
      })
      .catch((e) => {
        if (!cancelled) setError(asNetworkErrorMessage(e, 'Dashboard load failed'))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-[#8da7cd]">Loading GitHub activity…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div role="alert" className="app-panel border-l-4 border-l-[#ff5b73] px-4 py-3 text-sm text-[#ffd5dc]">
          {error}
        </div>
      </div>
    )
  }

  const empty = !data || data.total_pr_scans === 0
  const severity = data?.severity_totals || { critical: 0, high: 0, medium: 0, low: 0 }
  const avgRisk = data?.avg_risk ?? 0

  return (
    <div className="terminal-grid mx-auto w-full max-w-[1540px] px-6 py-8">
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <DashboardHeading
          kicker="GitHub PR activity"
          title="Security posture"
          body="Track pull-request risk, policy failures, and repository coverage from one readable command surface."
        />
        <div className="flex items-center gap-2">
          <AtlasLiveBadge source="github" />
          {!empty && (
            <a
              href="/api/dashboard/github/export.csv"
              className="app-secondary-button terminal-mono inline-flex items-center gap-2 px-4 py-2 text-sm font-medium"
            >
              Export CSV
              <span className="text-xs">↓</span>
            </a>
          )}
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="app-primary-button terminal-mono inline-flex items-center gap-2 px-4 py-2 text-sm font-medium"
          >
            Connect a repo
            <span className="text-base leading-none">→</span>
          </a>
        </div>
      </div>

      <div className="mb-3">
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
      </div>

      <div className="mb-6">
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

      <section className="mb-6 border border-carbon-border bg-white px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
          <span className="text-[#13aa52]">Atlas features in this view:</span>
          <span className="border border-carbon-border bg-carbon-layer px-2 py-0.5 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">Vector Search</span>
          <span className="border border-carbon-border bg-carbon-layer px-2 py-0.5 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">Atlas Search</span>
          <span className="border border-carbon-border bg-carbon-layer px-2 py-0.5 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">$rankFusion</span>
          <span className="border border-carbon-border bg-carbon-layer px-2 py-0.5 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">Time-Series</span>
          <span className="border border-carbon-border bg-carbon-layer px-2 py-0.5 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">Change Streams</span>
        </div>
      </section>

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
        <section className="terminal-panel mt-8 px-8 py-12 text-center">
          <p className="terminal-label text-[11px] font-semibold">No PR scans yet</p>
          <h2 className="terminal-mono mt-3 text-2xl font-semibold uppercase text-white">
            Install the GitHub App to start auto-reviewing pull requests
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm text-[#9bb2d6]">
            PromptShield runs on every PR, posts inline comments on risky prompt code, and
            writes a Check Run gate that can block merging when the risk score crosses your
            configured threshold.
          </p>
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="app-primary-button mt-5 inline-flex items-center gap-2 px-5 py-2 text-sm font-medium"
          >
            Install GitHub App
            <span className="text-base leading-none">→</span>
          </a>
        </section>
      ) : (
        <>
          <section className="terminal-panel relative overflow-hidden">
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-[#0c1a2b] via-[#091423] to-[#07111d]" />
            <div className="relative grid gap-5 px-6 py-6 xl:grid-cols-[320px,1fr]">
              <div className="terminal-soft flex flex-col items-center px-6 py-6 text-center">
                <div className="terminal-label text-[10px] font-semibold">Average risk</div>
                <div className="mt-4">
                  <RiskGauge score={Math.round(avgRisk)} size={176} />
                </div>
                <p className="mt-4 max-w-[24ch] text-[13px] leading-[1.6] text-[#9bb2d6]">
                  Mean score across {data.total_pr_scans} reviewed PR
                  {data.total_pr_scans === 1 ? '' : 's'}, with policy gate context applied.
                </p>
                <div className="mt-4">
                  <TrendDelta daily={data.daily_velocity} />
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <Tile
                  label="Total PR scans"
                  value={data.total_pr_scans ?? 0}
                  hint="All pull requests reviewed across connected repositories."
                />
                <Tile
                  label={`Gate failures (≥${data.threshold ?? 70})`}
                  value={data.gate_failures ?? 0}
                  accent="#ff7d8f"
                  hint="Pull requests blocked before merge by policy threshold."
                />
                <Tile
                  label="Repos covered"
                  value={data.repos_covered ?? 0}
                  hint="Unique repositories currently sending review activity."
                />
                <Tile
                  label="Avg findings / PR"
                  value={
                    data.avg_findings_per_pr != null
                      ? data.avg_findings_per_pr.toFixed(2)
                      : '0.00'
                  }
                  accent="#7db2ff"
                  hint="Average number of flagged findings per reviewed pull request."
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

          {data.daily_velocity?.length > 0 && (
            <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Risk trend (14 days)
              </h2>
              <div className="h-56 w-full">
                <ResponsiveContainer>
                  <AreaChart
                    data={data.daily_velocity.map((p) => ({
                      ...p,
                      label: shortDay(p.date),
                    }))}
                    margin={{ top: 8, right: 16, left: 0, bottom: 8 }}
                  >
                    <defs>
                      <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
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
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke="#6f6f6f"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="avg_risk"
                      stroke="#0f62fe"
                      strokeWidth={2}
                      fill="url(#riskFill)"
                      name="Avg risk"
                      animationDuration={700}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
          )}

          {atlasTimeline?.length > 0 && (
            <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Atlas time-series risk (30 days, 7d rolling avg)
              </h2>
              <div className="h-56 w-full">
                <ResponsiveContainer>
                  <AreaChart
                    data={atlasTimeline.map((p) => ({
                      ...p,
                      label: shortDay(p.ts),
                    }))}
                    margin={{ top: 8, right: 16, left: 0, bottom: 8 }}
                  >
                    <defs>
                      <linearGradient id="atlasRiskFill" x1="0" y1="0" x2="0" y2="1">
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
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke="#6f6f6f"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="risk_score"
                      stroke="#13aa52"
                      strokeWidth={1.7}
                      fill="url(#atlasRiskFill)"
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
                </ResponsiveContainer>
              </div>
            </section>
          )}

          <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Top vulnerability types
            </h2>
            {data.top_finding_types?.length > 0 ? (
              <div className="h-56 w-full">
                <ResponsiveContainer>
                  <BarChart
                    layout="vertical"
                    data={data.top_finding_types}
                    margin={{ top: 4, right: 24, left: 32, bottom: 4 }}
                  >
                    <CartesianGrid stroke="#e0e0e0" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      stroke="#6f6f6f"
                      tickLine={false}
                      axisLine={{ stroke: '#c6c6c6' }}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <YAxis
                      type="category"
                      dataKey="type"
                      width={170}
                      stroke="#6f6f6f"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#8a3ffc" animationDuration={700} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
                No findings yet.
              </p>
            )}
          </section>

          <section className="mt-6">
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Recent pull requests
            </h2>
            <div className="overflow-x-auto border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-carbon-border bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
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
                        <defs>
                          <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#5ea8ff" stopOpacity={0.45} />
                            <stop offset="100%" stopColor="#5ea8ff" stopOpacity={0.05} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" vertical={false} />
                        <XAxis
                          dataKey="label"
                          stroke="#86a2cb"
                          tickLine={false}
                          axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }}
                          tick={{ fontSize: 11, fontFamily: 'IBM Plex Mono', fill: '#86a2cb' }}
                        />
                        <YAxis
                          domain={[0, 100]}
                          stroke="#86a2cb"
                          tickLine={false}
                          axisLine={false}
                          tick={{ fontSize: 11, fontFamily: 'IBM Plex Mono', fill: '#86a2cb' }}
                        />
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                        <Area
                          type="monotone"
                          dataKey="avg_risk"
                          stroke="#5ea8ff"
                          strokeWidth={2}
                          fill="url(#riskFill)"
                          name="Avg risk"
                          animationDuration={700}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </FrostSection>
              )}

              <section>
                <SectionHeading
                  title="Recent pull requests"
                  meta={`${data.recent?.length || 0} most recent`}
                />
                <div className="terminal-panel overflow-x-auto">
                  <table className="terminal-table w-full text-left">
                    <thead>
                      <tr className="border-b border-white/10">
                        {[
                          'Repository',
                          'PR',
                          'Commit',
                          'Score',
                          'State',
                          'Time',
                          '',
                        ].map((header, index) => (
                          <th
                            key={index}
                            className="terminal-label px-4 py-3 text-[10px] font-semibold"
                          >
                            {header}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.recent.map((scan) => (
                        <PRScanRow
                          key={scan.id}
                          scan={scan}
                          threshold={data.threshold}
                          onSelect={onSelectScan}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>

            <div className="space-y-6">
              <FrostSection>
                <SectionHeading
                  title="Severity mix"
                  meta={`${
                    (severity.critical || 0) +
                    (severity.high || 0) +
                    (severity.medium || 0) +
                    (severity.low || 0)
                  } findings total`}
                />
                <StackedSeverityBar severity={severity} />
              </FrostSection>

              <FrostSection>
                <SectionHeading title="Top vulnerability types" meta="Most frequent findings" />
                <RankedFindingTypes items={data.top_finding_types || []} />
              </FrostSection>

              <FrostSection>
                <SectionHeading title="Risk by repository" meta="Average score by repo" />
                <RepoRiskList items={data.by_repo || []} />
              </FrostSection>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
