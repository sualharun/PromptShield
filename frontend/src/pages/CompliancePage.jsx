import { useEffect, useMemo, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { asNetworkErrorMessage, fetchWithTimeout } from '../lib/fetchWithTimeout.js'

const TOOLTIP_STYLE = {
  border: '1px solid rgba(129, 159, 224, 0.16)',
  background: 'rgba(7, 17, 31, 0.96)',
  color: '#f5f8ff',
  fontSize: 12,
  fontFamily: 'IBM Plex Sans, sans-serif',
  borderRadius: 16,
  padding: '8px 10px',
}

function shortDay(d) {
  try {
    const dt = new Date(d)
    return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  } catch {
    return d
  }
}

function SectionTitle({ title }) {
  return (
    <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-[#de715d]">
      {title}
    </h2>
  )
}

export default function CompliancePage() {
  const [compliance, setCompliance] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [audit, setAudit] = useState([])
  const [readiness, setReadiness] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([
      fetchWithTimeout('/api/dashboard/compliance').then((r) => (r.ok ? r.json() : null)),
      fetchWithTimeout('/api/risk-timeline?source=github&days=30').then((r) =>
        r.ok ? r.json() : null
      ),
      fetchWithTimeout('/api/audit-logs?source=github&limit=30').then((r) =>
        r.ok ? r.json() : []
      ),
      fetchWithTimeout('/api/enterprise/readiness').then((r) => (r.ok ? r.json() : null)),
    ])
      .then(([c, t, a, e]) => {
        if (cancelled) return
        setCompliance(c)
        setTimeline(t)
        setAudit(a || [])
        setReadiness(e)
      })
      .catch((e) => {
        if (!cancelled) setError(asNetworkErrorMessage(e, 'Compliance load failed'))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const cweData = useMemo(() => compliance?.cwe?.slice(0, 8) || [], [compliance])
  const owaspData = useMemo(() => compliance?.owasp?.slice(0, 8) || [], [compliance])

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-[#8da7cd]">Loading compliance posture…</p>
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

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="app-section-label text-[11px] font-semibold">
            Compliance · auditability · enterprise readiness
          </p>
          <h1 className="mt-3 font-display text-5xl leading-[0.98] tracking-[-0.05em] text-carbon-text">
            Compliance and governance
          </h1>
          <p className="mt-3 max-w-2xl text-[14px] leading-relaxed text-carbon-text-secondary">
            Findings are mapped to CWE and OWASP LLM categories with an audit trail for who scanned what and when.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a href="/api/reports/compliance.csv" className="app-secondary-button inline-flex items-center gap-2 px-4 py-2 text-sm font-medium">
            Export CSV
          </a>
          <a href="/api/reports/compliance.pdf" className="app-primary-button inline-flex items-center gap-2 px-4 py-2 text-sm font-medium">
            Export PDF
          </a>
        </div>
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="app-panel-soft px-5 py-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-[#58532a]">Total findings</div>
          <div className="mt-2 text-3xl font-light tabular-nums text-carbon-text">{compliance?.total_findings ?? 0}</div>
        </div>
        <div className="app-panel-soft px-5 py-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-[#58532a]">Compliant PR ratio</div>
          <div className="mt-2 text-3xl font-light tabular-nums text-[#16213e]">{(compliance?.compliant_pr_ratio ?? 0).toFixed(1)}%</div>
        </div>
        <div className="app-panel-soft px-5 py-5">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-[#58532a]">Risk trend delta (30d)</div>
          <div className={`mt-2 text-3xl font-light tabular-nums ${(timeline?.trend_delta ?? 0) <= 0 ? 'text-[#98e0ff]' : 'text-[#ff9cab]'}`}>
            {timeline?.trend_delta != null ? `${timeline.trend_delta > 0 ? '+' : ''}${timeline.trend_delta}` : '0'}
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-6 md:grid-cols-2">
        <div className="app-panel p-5">
          <SectionTitle title="Top CWE mappings" />
          <div className="h-64 w-full">
            <ResponsiveContainer>
              <BarChart data={cweData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
                <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" vertical={false} />
                <XAxis dataKey="key" tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#8fbcff" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="app-panel p-5">
          <SectionTitle title="OWASP LLM categories" />
          <div className="h-64 w-full">
            <ResponsiveContainer>
              <BarChart data={owaspData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
                <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" vertical={false} />
                <XAxis dataKey="key" tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#5ec8ff" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="app-panel mt-6 p-5">
        <SectionTitle title="Enterprise readiness (1000 repos)" />
        <div className="mb-3 h-3 w-full overflow-hidden rounded-full border border-carbon-border">
          <div
            className="h-full rounded-full bg-[#5ea8ff]"
            style={{ width: `${Math.min(100, readiness?.readiness_percent || 0)}%` }}
          />
        </div>
        <p className="text-sm text-carbon-text-secondary">
          {readiness?.repos_covered ?? 0} repos covered / {readiness?.target_repos ?? 1000} target · readiness {readiness?.readiness_percent ?? 0}%
        </p>
        <ul className="mt-3 space-y-1 text-[12px] text-carbon-text-tertiary">
          {(readiness?.indicators || []).map((indicator) => (
            <li key={indicator}>- {indicator}</li>
          ))}
        </ul>
      </section>

      <section className="app-panel mt-6 p-5">
        <SectionTitle title="Risk timeline (30 days)" />
        <div className="h-64 w-full">
          <ResponsiveContainer>
            <LineChart data={(timeline?.points || []).map((p) => ({ ...p, label: shortDay(p.date) }))} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
              <CartesianGrid stroke="rgba(129, 159, 224, 0.12)" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={{ stroke: 'rgba(129, 159, 224, 0.12)' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#86a2cb' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="avg_risk" stroke="#5ea8ff" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="app-panel mt-6">
        <div className="border-b border-carbon-border px-4 py-3">
          <SectionTitle title="Audit trail" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-carbon-border">
                {['Time', 'Actor', 'Action', 'Repo', 'PR', 'Details'].map((header) => (
                  <th key={header} className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-[#58532a]">
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((item) => (
                <tr key={item.id} className="app-table-row border-b border-carbon-border">
                  <td className="px-4 py-2 text-[12px] text-carbon-text-tertiary">{new Date(item.created_at).toLocaleString()}</td>
                  <td className="px-4 py-2 font-mono text-[12px] text-carbon-text">{item.actor}</td>
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary">{item.action}</td>
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary">{item.repo_full_name || '-'}</td>
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary">{item.pr_number ?? '-'}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-carbon-text-tertiary">{JSON.stringify(item.details || {})}</td>
                </tr>
              ))}
              {!audit.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-5 text-sm text-carbon-text-tertiary">No audit events yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 grid gap-6 md:grid-cols-2">
        <div className="app-panel p-5">
          <h3 className="text-[13px] font-semibold text-carbon-text">Why this is different</h3>
          <p className="mt-2 text-sm text-carbon-text-secondary">
            PromptShield scans during pull request review to prevent risky prompt code before merge, instead of waiting for runtime-only controls after deploy.
          </p>
        </div>
        <div className="app-panel p-5">
          <h3 className="text-[13px] font-semibold text-carbon-text">Open-source posture</h3>
          <p className="mt-2 text-sm text-carbon-text-secondary">
            Self-hostable, community-driven, and designed to run inside your SDLC without vendor lock-in.
          </p>
        </div>
      </section>
    </div>
  )
}
