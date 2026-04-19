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
import {
  buildAgentActivity,
  matchAgentAccount,
  providerMeta,
} from '../lib/agentAccounts.js'

const INSTALL_URL =
  import.meta.env?.VITE_GITHUB_APP_INSTALL_URL || '#'

const TOOLTIP_STYLE = {
  border: '1px solid rgba(222, 113, 93, 0.32)',
  background: '#f7f5ef',
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
    <div className="border border-[#de715d]/24 bg-white px-5 py-5">
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-[#58532a]">
        {label}
      </div>
      <div
        className="mt-2 font-light text-3xl tabular-nums"
        style={{ color: accent || '#16213e' }}
      >
        {value}
      </div>
      {hint && (
        <div className="mt-1 text-[11px] text-[#4b5876]">
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
      <p className="text-sm text-[#4b5876]">
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
      <div className="flex h-3 w-full overflow-hidden border border-[#de715d]/28">
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
            <span className="text-[#4b5876]">
              {s.label}
            </span>
            <span className="ml-auto font-mono tabular-nums text-[#16213e]">
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
      <span className="text-[11px] uppercase tracking-[0.1em] text-[#4b5876]">
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
      <span className="text-[#4b5876]">
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

function ProviderBadge({ provider }) {
  const meta = providerMeta(provider)
  return (
    <span
      className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] ${meta.tone}`}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.accent }} />
      {meta.label}
    </span>
  )
}

function ConnectedAgents({ accounts, recent }) {
  if (!accounts.length) {
    return (
      <section className="mt-6 border border-dashed border-[#de715d]/38 bg-white px-6 py-6">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
          Connected coding agents
        </h2>
        <p className="mt-3 max-w-2xl text-[13px] leading-[1.6] text-[#4b5876]">
          Add Codex, Claude, and Cursor accounts in the Agents view to differentiate which provider
          opened a PR and which coding-agent actions are currently being processed.
        </p>
      </section>
    )
  }

  return (
    <section className="mt-6">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
          Connected coding agents
        </h2>
        <span className="text-[11px] text-[#4b5876]">
          Attributed from GitHub authors
        </span>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {accounts.map((account) => {
          const matched = recent.filter((scan) => matchAgentAccount([account], scan))
          const highestRisk = matched.length ? Math.max(...matched.map((scan) => scan.risk_score || 0)) : 0
          return (
            <article
              key={account.id}
              className="border border-[#de715d]/28 bg-white px-5 py-5"
            >
              <div className="flex items-center justify-between gap-3">
                <ProviderBadge provider={account.provider} />
                <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#58532a]">
                  connected
                </span>
              </div>
              <div className="mt-4 text-lg font-medium text-[#16213e]">
                {account.displayName}
              </div>
              <div className="mt-1 font-mono text-[12px] text-[#4b5876]">
                @{account.githubHandle}
              </div>
              <div className="mt-5 grid grid-cols-2 gap-4 border-t border-[#de715d]/20 pt-4">
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#58532a]">
                    Processed PRs
                  </div>
                  <div className="mt-1 text-2xl font-light text-[#16213e]">
                    {matched.length}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#58532a]">
                    Max risk
                  </div>
                  <div className="mt-1 text-2xl font-light" style={{ color: avgRiskColor(highestRisk) }}>
                    {matched.length ? highestRisk : '—'}
                  </div>
                </div>
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}

function AgentProcessingFeed({ accounts, recent }) {
  const activity = buildAgentActivity(accounts, recent).slice(0, 6)

  if (!activity.length) return null

  return (
    <section className="mt-6 border border-[#de715d]/28 bg-white p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
          Agent actions being processed
        </h2>
        <span className="text-[11px] text-[#4b5876]">
          Connected providers only
        </span>
      </div>
      <div className="space-y-3">
        {activity.map((item) => (
          <div
            key={item.id}
            className="flex items-start justify-between gap-4 border border-[#de715d]/22 bg-[#f7f5ef] px-4 py-3"
          >
            <div>
              <div className="flex items-center gap-2">
                <ProviderBadge provider={item.account.provider} />
                <span className="text-[12px] font-medium text-[#16213e]">
                  {item.account.displayName}
                </span>
              </div>
              <div className="mt-2 text-[13px] leading-[1.55] text-[#16213e]">
                PR #{item.scan.pr_number ?? '—'} in {item.scan.repo_full_name || 'unknown repo'}
              </div>
              <div className="mt-1 text-[12px] leading-[1.55] text-[#4b5876]">
                {item.summary}
              </div>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#58532a]">
                Phase
              </div>
              <div className="mt-1 text-[12px] font-medium text-[#de715d]">
                {item.phase}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

export default function DashboardPage({ onSelectScan, agentAccounts = [] }) {
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
      <div className="mx-auto w-full max-w-[1180px] px-6 py-12">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-[#4b5876]">
          Loading GitHub activity…
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-[1180px] px-6 py-12">
        <div
          role="alert"
          className="border-l-4 border-[#de715d] border-y border-r border-[#de715d]/35 bg-[#fff1ec] px-4 py-3 text-sm text-[#8f3c2d]"
        >
          {error}
        </div>
      </div>
    )
  }

  const empty = !data || data.total_pr_scans === 0
  const severity = data?.severity_totals || { critical: 0, high: 0, medium: 0, low: 0 }
  const avgRisk = data?.avg_risk ?? 0
  const recent = data?.recent || []

  return (
    <div className="mx-auto w-full max-w-[1180px] px-6 py-10">
      <div className="mb-8 flex flex-col items-center gap-4 text-center">
        <div>
          <p className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[#58532a]">
            <span className="h-1.5 w-1.5 bg-[#de715d]" />
            GitHub PR activity · Dashboard
          </p>
          <h1 className="mt-3 font-light text-[clamp(2.2rem,4vw,3rem)] leading-tight text-[#16213e]">
            Security posture
          </h1>
          <p className="mx-auto mt-2 max-w-2xl text-[14px] leading-7 text-[#4b5876]">
            Every pull request reviewed by the PromptShield bot — scored,
            gated, and tracked across repos.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-2">
          {!empty && (
            <a
              href="/api/dashboard/github/export.csv"
              className="inline-flex items-center gap-2 border border-[#16213e] bg-white px-4 py-2 text-sm font-medium text-[#16213e] transition-colors hover:border-[#de715d] hover:text-[#de715d]"
            >
              Export CSV
              <span className="text-xs">↓</span>
            </a>
          )}
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 border border-[#de715d] bg-[#de715d] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#cb624f]"
          >
            Connect a repo
            <span className="text-base leading-none">→</span>
          </a>
        </div>
      </div>

      <ConnectedAgents accounts={agentAccounts} recent={recent} />

      {empty ? (
        <section className="mt-8 border border-[#de715d]/28 bg-white px-8 py-12 text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#58532a]">
            No PR scans yet
          </p>
          <h2 className="mt-2 font-light text-2xl text-[#16213e]">
            Install the GitHub App to start auto-reviewing pull requests
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-7 text-[#4b5876]">
            PromptShield runs on every PR — posts inline comments on risky
            prompt code and a Check Run gate that can block merging when the
            risk score crosses the configured threshold.
          </p>
          <a
            href={INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="mt-5 inline-flex items-center gap-2 border border-[#de715d] bg-[#de715d] px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-[#cb624f]"
          >
            Install GitHub App
            <span className="text-base leading-none">→</span>
          </a>
        </section>
      ) : (
        <>
          <section className="relative overflow-hidden border border-[#de715d]/28 bg-[#f7f5ef]">
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-[#e1e3eb] via-[#f7f5ef] to-white" />
            <div className="pointer-events-none absolute -right-20 -top-20 h-72 w-72 rounded-full bg-[#de715d]/10 blur-3xl" />
            <div className="relative grid gap-6 px-6 py-6 md:grid-cols-[260px,1fr] md:items-center">
              <div className="flex flex-col items-center">
                <RiskGauge score={Math.round(avgRisk)} size={180} />
                <div className="mt-3 text-[11px] font-medium uppercase tracking-[0.1em] text-[#58532a]">
                  Average risk across {data.total_pr_scans} scan
                  {data.total_pr_scans === 1 ? '' : 's'}
                </div>
                <div className="mt-2">
                  <TrendDelta daily={data.daily_velocity} />
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <Tile
                  label="Total PR scans"
                  value={data.total_pr_scans ?? 0}
                  hint="Across all connected repos"
                />
                <Tile
                  label={`Gate failures (≥${data.threshold ?? 70})`}
                  value={data.gate_failures ?? 0}
                  accent="#de715d"
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
                  accent="#58532a"
                  hint="Signal density"
                />
              </div>
            </div>
          </section>

          <section className="mt-6 border border-[#de715d]/28 bg-white p-5">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
                Severity mix
              </h2>
              <span className="text-[11px] text-[#4b5876]">
                {(severity.critical || 0) +
                  (severity.high || 0) +
                  (severity.medium || 0) +
                  (severity.low || 0)}{' '}
                findings total
              </span>
            </div>
            <StackedSeverityBar severity={severity} />
          </section>

          <AgentProcessingFeed accounts={agentAccounts} recent={recent} />

          {data.daily_velocity?.length > 0 && (
            <section className="mt-6 border border-[#de715d]/28 bg-white p-5">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
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
                        <stop offset="0%" stopColor="#16213e" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#16213e" stopOpacity={0.05} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#ddd7d1" vertical={false} />
                    <XAxis
                      dataKey="label"
                      stroke="#4b5876"
                      tickLine={false}
                      axisLine={{ stroke: '#d6d4cf' }}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke="#4b5876"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="avg_risk"
                      stroke="#16213e"
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

          <section className="mt-6 border border-[#de715d]/28 bg-white p-5">
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
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
                    <CartesianGrid stroke="#ddd7d1" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      stroke="#4b5876"
                      tickLine={false}
                      axisLine={{ stroke: '#d6d4cf' }}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <YAxis
                      type="category"
                      dataKey="type"
                      width={170}
                      stroke="#4b5876"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                    />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#de715d" animationDuration={700} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <p className="text-sm text-[#4b5876]">
                No findings yet.
              </p>
            )}
          </section>

          <section className="mt-6">
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
              Recent pull requests
            </h2>
            <div className="overflow-x-auto border border-[#de715d]/28 bg-white">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[#de715d]/24 bg-[#e1e3eb]">
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
                        className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-[#58532a]"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recent.map((s) => (
                    <PRScanRow
                      key={s.id}
                      scan={s}
                      threshold={data.threshold}
                      onSelect={onSelectScan}
                      agentAccount={matchAgentAccount(agentAccounts, s)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {data.by_repo?.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-[#58532a]">
                Risk by repository
              </h2>
              <div className="border border-[#de715d]/28 bg-white p-5">
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
                      <CartesianGrid stroke="#ddd7d1" horizontal={false} />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        stroke="#4b5876"
                        tickLine={false}
                        axisLine={{ stroke: '#d6d4cf' }}
                        tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={160}
                        stroke="#4b5876"
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
