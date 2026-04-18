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

function Tile({ label, value, accent, hint }) {
  return (
    <div className="bg-white px-5 py-5 dark:bg-ibm-gray-90">
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {label}
      </div>
      <div
        className="mt-2 font-light text-3xl tabular-nums"
        style={{ color: accent || 'var(--carbon-text)' }}
      >
        {value}
      </div>
      {hint && (
        <div className="mt-1 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
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

export default function DashboardPage({ onSelectScan }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    fetchWithTimeout('/api/dashboard/github')
      .then((r) => {
        if (!r.ok) throw new Error(`Dashboard load failed (${r.status})`)
        return r.json()
      })
      .then((d) => {
        if (!cancelled) setData(d)
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
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Loading GitHub activity…
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
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
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-purple-70 dark:text-ibm-purple-40">
            <span className="h-1.5 w-1.5 bg-ibm-purple-60" />
            GitHub PR activity · Enterprise view
          </p>
          <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
            Security posture
          </h1>
          <p className="mt-1 max-w-xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Every pull request reviewed by the PromptShield bot — scored,
            gated, and tracked across repos.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!empty && (
            <a
              href="/api/dashboard/github/export.csv"
              className="inline-flex items-center gap-2 border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
            >
              Export CSV
              <span className="text-xs">↓</span>
            </a>
          )}
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
          <section className="relative overflow-hidden border border-carbon-border dark:border-ibm-gray-80">
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-ibm-blue-10 via-white to-white dark:from-ibm-blue-90/30 dark:via-ibm-gray-100 dark:to-ibm-gray-100" />
            <div className="pointer-events-none absolute -right-20 -top-20 h-72 w-72 rounded-full bg-ibm-purple-50/20 blur-3xl" />
            <div className="relative grid gap-6 px-6 py-6 md:grid-cols-[260px,1fr] md:items-center">
              <div className="flex flex-col items-center">
                <RiskGauge score={Math.round(avgRisk)} size={180} />
                <div className="mt-3 text-[11px] font-medium uppercase tracking-[0.1em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                  Average risk across {data.total_pr_scans} scan
                  {data.total_pr_scans === 1 ? '' : 's'}
                </div>
                <div className="mt-2">
                  <TrendDelta daily={data.daily_velocity} />
                </div>
              </div>
              <div className="grid gap-px bg-carbon-border dark:bg-ibm-gray-80 sm:grid-cols-2">
                <Tile
                  label="Total PR scans"
                  value={data.total_pr_scans ?? 0}
                  hint="Across all connected repos"
                />
                <Tile
                  label={`Gate failures (≥${data.threshold ?? 70})`}
                  value={data.gate_failures ?? 0}
                  accent="#a2191f"
                  hint="Blocked before merge"
                />
                <Tile
                  label="Repos covered"
                  value={data.repos_covered ?? 0}
                  hint="Unique repositories"
                />
                <Tile
                  label="Avg findings / PR"
                  value={
                    data.avg_findings_per_pr != null
                      ? data.avg_findings_per_pr.toFixed(2)
                      : '0.00'
                  }
                  accent="#8a3ffc"
                  hint="Signal density"
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

          {data.by_repo?.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Risk by repository
              </h2>
              <div className="border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
                <div className="h-64 w-full">
                  <ResponsiveContainer>
                    <BarChart
                      layout="vertical"
                      data={data.by_repo.map((r) => ({
                        name: r.repo_full_name,
                        avg_risk: r.avg_risk,
                        scan_count: r.scan_count,
                      }))}
                      margin={{ top: 8, right: 24, left: 32, bottom: 8 }}
                    >
                      <CartesianGrid stroke="#e0e0e0" horizontal={false} />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={{ stroke: '#c6c6c6' }}
                        tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={160}
                        stroke="#6f6f6f"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
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
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}
