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
  border: '1px solid #e0e0e0',
  background: '#ffffff',
  fontSize: 12,
  fontFamily: 'IBM Plex Sans, sans-serif',
  borderRadius: 0,
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
  const owaspData = useMemo(
    () => compliance?.owasp?.slice(0, 8) || [],
    [compliance]
  )

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Loading compliance posture…
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

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
            Compliance · auditability · enterprise readiness
          </p>
          <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
            Compliance and governance
          </h1>
          <p className="mt-1 max-w-2xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Findings are mapped to CWE and OWASP LLM categories with an audit trail for who scanned what and when.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href="/api/reports/compliance.csv"
            className="inline-flex items-center gap-2 border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            Export CSV
          </a>
          <a
            href="/api/reports/compliance.pdf"
            className="inline-flex items-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70"
          >
            Export PDF
          </a>
        </div>
      </div>

      <section className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white px-5 py-5 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Total findings</div>
          <div className="mt-2 font-light text-3xl tabular-nums">{compliance?.total_findings ?? 0}</div>
        </div>
        <div className="bg-white px-5 py-5 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Compliant PR ratio</div>
          <div className="mt-2 font-light text-3xl tabular-nums text-ibm-green-60">{(compliance?.compliant_pr_ratio ?? 0).toFixed(1)}%</div>
        </div>
        <div className="bg-white px-5 py-5 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Risk trend delta (30d)</div>
          <div className={`mt-2 font-light text-3xl tabular-nums ${(timeline?.trend_delta ?? 0) <= 0 ? 'text-ibm-green-60' : 'text-ibm-red-60'}`}>
            {timeline?.trend_delta != null ? `${timeline.trend_delta > 0 ? '+' : ''}${timeline.trend_delta}` : '0'}
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">Top CWE mappings</h2>
          <div className="h-64 w-full">
            <ResponsiveContainer>
              <BarChart data={cweData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
                <CartesianGrid stroke="#e0e0e0" vertical={false} />
                <XAxis dataKey="key" tick={{ fontSize: 11 }} tickLine={false} axisLine={{ stroke: '#c6c6c6' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#8a3ffc" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">OWASP LLM categories</h2>
          <div className="h-64 w-full">
            <ResponsiveContainer>
              <BarChart data={owaspData} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
                <CartesianGrid stroke="#e0e0e0" vertical={false} />
                <XAxis dataKey="key" tick={{ fontSize: 11 }} tickLine={false} axisLine={{ stroke: '#c6c6c6' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#0f62fe" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">Enterprise readiness (1000 repos)</h2>
        <div className="mb-3 h-3 w-full overflow-hidden border border-carbon-border dark:border-ibm-gray-80">
          <div
            className="h-full bg-ibm-blue-60"
            style={{ width: `${Math.min(100, readiness?.readiness_percent || 0)}%` }}
          />
        </div>
        <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
          {readiness?.repos_covered ?? 0} repos covered / {readiness?.target_repos ?? 1000} target · readiness {readiness?.readiness_percent ?? 0}%
        </p>
        <ul className="mt-3 space-y-1 text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          {(readiness?.indicators || []).map((i) => (
            <li key={i}>- {i}</li>
          ))}
        </ul>
      </section>

      <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">Risk timeline (30 days)</h2>
        <div className="h-64 w-full">
          <ResponsiveContainer>
            <LineChart data={(timeline?.points || []).map((p) => ({ ...p, label: shortDay(p.date) }))} margin={{ top: 8, right: 16, left: 8, bottom: 8 }}>
              <CartesianGrid stroke="#e0e0e0" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} tickLine={false} axisLine={{ stroke: '#c6c6c6' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="avg_risk" stroke="#0f62fe" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="mt-6 border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="border-b border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">Audit trail</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-carbon-border dark:border-ibm-gray-80">
                {['Time', 'Actor', 'Action', 'Repo', 'PR', 'Details'].map((h) => (
                  <th key={h} className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id} className="border-b border-carbon-border/70 dark:border-ibm-gray-80/70">
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">{new Date(a.created_at).toLocaleString()}</td>
                  <td className="px-4 py-2 font-mono text-[12px]">{a.actor}</td>
                  <td className="px-4 py-2 text-[12px]">{a.action}</td>
                  <td className="px-4 py-2 text-[12px]">{a.repo_full_name || '-'}</td>
                  <td className="px-4 py-2 text-[12px]">{a.pr_number ?? '-'}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">{JSON.stringify(a.details || {})}</td>
                </tr>
              ))}
              {!audit.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-5 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">No audit events yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h3 className="text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">Why this is different</h3>
          <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            Protect AI and Lakera mostly focus on runtime monitoring. PromptShield scans during pull request review to prevent risky prompt code before merge.
          </p>
        </div>
        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h3 className="text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">Open source posture</h3>
          <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            Self-hostable, community-driven, and designed to run inside your SDLC without vendor lock-in.
          </p>
        </div>
      </section>
    </div>
  )
}
