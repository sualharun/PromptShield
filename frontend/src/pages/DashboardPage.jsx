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

const INSTALL_URL = import.meta.env?.VITE_GITHUB_APP_INSTALL_URL || '#'

const TOOLTIP_STYLE = {
  border: '1px solid rgba(129, 159, 224, 0.16)',
  background: 'rgba(7, 17, 31, 0.96)',
  color: '#f5f8ff',
  fontSize: 12,
  fontFamily: 'Sora, sans-serif',
  borderRadius: 16,
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
        className="terminal-mono mt-2 text-3xl font-light tabular-nums"
        style={{ color: accent || '#f5f8ff' }}
      >
        {value}
      </div>
      {hint && <div className="mt-1 text-[11px] text-[#8da7cd]">{hint}</div>}
    </div>
  )
}

function FrostSection({ children, className = '' }) {
  return <section className={`terminal-panel p-5 ${className}`}>{children}</section>
}

function DashboardHeading({ kicker, title, body }) {
  return (
    <div>
      <p className="app-section-label text-[11px] font-semibold">{kicker}</p>
      <h1 className="mt-3 text-4xl font-semibold leading-[1.02] tracking-[-0.04em] text-white">
        {title}
      </h1>
      <p className="mt-3 max-w-2xl text-[14px] leading-relaxed text-[#9bb2d6]">
        {body}
      </p>
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
    <div className="terminal-grid mx-auto w-full max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <DashboardHeading
          kicker="GitHub PR activity"
          title="Security posture"
          body="Every pull request reviewed by the PromptShield bot, scored against policy, and tracked across repositories from one command surface."
        />
        <div className="flex items-center gap-2">
          {!empty && (
            <a
              href="/api/dashboard/github/export.csv"
              className="app-secondary-button inline-flex items-center gap-2 px-4 py-2 text-sm font-medium"
            >
              Export CSV
              <span className="text-xs">↓</span>
            </a>
          )}
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="app-primary-button inline-flex items-center gap-2 px-4 py-2 text-sm font-medium"
          >
            Connect a repo
            <span className="text-base leading-none">→</span>
          </a>
        </div>
      </div>

      {empty ? (
        <section className="terminal-panel mt-8 px-8 py-12 text-center">
          <p className="terminal-label text-[11px] font-semibold">No PR scans yet</p>
          <h2 className="mt-3 text-3xl font-semibold text-white">
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
            <div className="relative grid gap-6 px-6 py-6 md:grid-cols-[260px,1fr] md:items-center">
              <div className="flex flex-col items-center">
                <RiskGauge score={Math.round(avgRisk)} size={180} />
                <div className="terminal-label mt-3 text-[10px] font-medium">
                  Average risk across {data.total_pr_scans} scan{data.total_pr_scans === 1 ? '' : 's'}
                </div>
                <div className="mt-2">
                  <TrendDelta daily={data.daily_velocity} />
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Tile
                  label="Total PR scans"
                  value={data.total_pr_scans ?? 0}
                  hint="Across all connected repos"
                />
                <Tile
                  label={`Gate failures (≥${data.threshold ?? 70})`}
                  value={data.gate_failures ?? 0}
                  accent="#ff7d8f"
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
                  accent="#7db2ff"
                  hint="Signal density"
                />
              </div>
            </div>
          </section>

          <FrostSection className="mt-6">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="terminal-label text-[10px] font-semibold">
                Severity mix
              </h2>
              <span className="text-[11px] text-[#8da7cd]">
                {(severity.critical || 0) +
                  (severity.high || 0) +
                  (severity.medium || 0) +
                  (severity.low || 0)}{' '}
                findings total
              </span>
            </div>
            <StackedSeverityBar severity={severity} />
          </FrostSection>

          {data.daily_velocity?.length > 0 && (
            <FrostSection className="mt-6">
              <h2 className="terminal-label mb-3 text-[10px] font-semibold">
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
                      tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#86a2cb' }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke="#86a2cb"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#86a2cb' }}
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

          <FrostSection className="mt-6">
              <h2 className="terminal-label mb-3 text-[10px] font-semibold">
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
                    <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      stroke="#86a2cb"
                      tickLine={false}
                      axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }}
                      tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#86a2cb' }}
                    />
                    <YAxis
                      type="category"
                      dataKey="type"
                      width={170}
                      stroke="#86a2cb"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#d7e6ff' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#5ea8ff" animationDuration={700} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <p className="text-sm text-[#8da7cd]">No findings yet.</p>
            )}
          </FrostSection>

          <section className="mt-6">
            <h2 className="terminal-label mb-3 text-[10px] font-semibold">
              Recent pull requests
            </h2>
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
                        className="terminal-label px-4 py-2 text-[10px] font-semibold"
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

          {data.by_repo?.length > 0 && (
            <section className="mt-6">
              <h2 className="terminal-label mb-3 text-[10px] font-semibold">
                Risk by repository
              </h2>
              <div className="terminal-panel p-5">
                <div className="h-64 w-full">
                  <ResponsiveContainer>
                    <BarChart
                      layout="vertical"
                      data={data.by_repo.map((repo) => ({
                        name: repo.repo_full_name,
                        avg_risk: repo.avg_risk,
                        scan_count: repo.scan_count,
                      }))}
                      margin={{ top: 8, right: 24, left: 32, bottom: 8 }}
                    >
                      <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" horizontal={false} />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        stroke="#86a2cb"
                        tickLine={false}
                        axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }}
                        tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#86a2cb' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={160}
                        stroke="#86a2cb"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fontSize: 11, fontFamily: 'Sora', fill: '#d7e6ff' }}
                      />
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                      <Bar dataKey="avg_risk" animationDuration={700}>
                        {data.by_repo.map((repo, index) => (
                          <Cell key={index} fill={avgRiskColor(repo.avg_risk)} />
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
