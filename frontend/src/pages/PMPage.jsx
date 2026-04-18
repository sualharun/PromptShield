import { useEffect, useState } from 'react'
import { useAuth } from '../auth/AuthContext.jsx'
import { asNetworkErrorMessage, fetchWithTimeout } from '../lib/fetchWithTimeout.js'

function fmtDuration(seconds) {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds}s`
  const m = Math.round(seconds / 60)
  if (m < 60) return `${m}m`
  const h = Math.round(m / 6) / 10
  if (h < 48) return `${h}h`
  const d = Math.round((h / 24) * 10) / 10
  return `${d}d`
}

function fmtDate(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export default function PMPage({ onSignIn }) {
  const { user, loading: authLoading } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const authorized = !!user && (user.role === 'admin' || user.role === 'pm')

  useEffect(() => {
    if (!authorized) {
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    fetchWithTimeout('/api/dashboard/pm', { credentials: 'include' })
      .then((r) => {
        if (!r.ok) throw new Error(`PM dashboard failed (${r.status})`)
        return r.json()
      })
      .then((body) => {
        if (!cancelled) setData(body)
      })
      .catch((e) => {
        if (!cancelled) setError(asNetworkErrorMessage(e, 'PM dashboard failed'))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [authorized])

  if (authLoading) {
    return (
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <div className="carbon-progress" />
      </div>
    )
  }

  if (!authorized) {
    return (
      <div className="mx-auto w-full max-w-3xl px-6 py-16">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
          Product-manager view
        </p>
        <h1 className="mt-2 font-light text-3xl text-carbon-text dark:text-ibm-gray-10">
          Sign in to view PM analytics
        </h1>
        <p className="mt-2 text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          The PM dashboard shows author leaderboards, blocked PRs, and
          remediation deltas. It requires a PM or admin role.
        </p>
        <button
          onClick={onSignIn}
          className="mt-6 inline-flex items-center border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white hover:bg-ibm-blue-70"
        >
          Sign in
        </button>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
          Loading PM analytics…
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <div className="border border-ibm-red-60 bg-[#fff1f1] px-4 py-3 text-sm text-ibm-red-60 dark:bg-ibm-red-60/10">
          {error}
        </div>
      </div>
    )
  }

  const byAuthor = data?.by_author || []
  const blocked = data?.blocked_prs || []
  const deltas = data?.remediation_deltas || []
  const repos = data?.repo_health || []

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
          Product-manager view · author accountability
        </p>
        <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
          Who ships risky code
        </h1>
        <p className="mt-1 max-w-2xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Aggregated from GitHub PR scans. Gate threshold ={' '}
          <span className="font-mono">{data?.gate_threshold ?? '—'}</span>.
        </p>
      </div>

      <section className="border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="border-b border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Authors by gate failures
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-carbon-border dark:border-ibm-gray-80">
                {['Author', 'Scans', 'Avg risk', 'Gate failures', 'Last scan'].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {byAuthor.map((a) => (
                <tr
                  key={a.author_login}
                  className="border-b border-carbon-border/70 dark:border-ibm-gray-80/70"
                >
                  <td className="px-4 py-2 font-mono text-[12px]">{a.author_login}</td>
                  <td className="px-4 py-2 text-[12px] tabular-nums">{a.scan_count}</td>
                  <td className="px-4 py-2 text-[12px] tabular-nums">{a.avg_risk}</td>
                  <td
                    className={`px-4 py-2 text-[12px] tabular-nums ${
                      a.gate_failures > 0 ? 'text-ibm-red-60' : 'text-ibm-green-60'
                    }`}
                  >
                    {a.gate_failures}
                  </td>
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
                    {fmtDate(a.last_scan_at)}
                  </td>
                </tr>
              ))}
              {!byAuthor.length && (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-5 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40"
                  >
                    No GitHub PR scans with attributable authors yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="border-b border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Recently blocked PRs
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-carbon-border dark:border-ibm-gray-80">
                {['Repo', 'PR', 'Title', 'Score', 'Author', 'Scanned'].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {blocked.map((b) => (
                <tr
                  key={b.scan_id}
                  className="border-b border-carbon-border/70 dark:border-ibm-gray-80/70"
                >
                  <td className="px-4 py-2 font-mono text-[12px]">
                    {b.repo_full_name || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px]">
                    {b.pr_url ? (
                      <a
                        href={b.pr_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-ibm-blue-60 hover:underline dark:text-ibm-blue-40"
                      >
                        #{b.pr_number}
                      </a>
                    ) : (
                      `#${b.pr_number ?? '—'}`
                    )}
                  </td>
                  <td className="max-w-xs truncate px-4 py-2 text-[12px]">
                    {b.pr_title || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px] font-semibold tabular-nums text-ibm-red-60">
                    {b.risk_score}
                  </td>
                  <td className="px-4 py-2 font-mono text-[12px]">
                    {b.author_login || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
                    {fmtDate(b.created_at)}
                  </td>
                </tr>
              ))}
              {!blocked.length && (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-5 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40"
                  >
                    No PRs have crossed the gate yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Remediation deltas
          </h2>
          <p className="mb-3 text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Time between a PR's first failing scan and its first passing scan.
          </p>
          <div className="space-y-1">
            {deltas.map((d) => (
              <div
                key={`${d.repo_full_name}-${d.pr_number}`}
                className="flex items-center justify-between border-b border-carbon-border/60 py-1 text-[12px] last:border-0 dark:border-ibm-gray-80/60"
              >
                <span className="font-mono">
                  {d.repo_full_name}#{d.pr_number}
                </span>
                <span
                  className={`tabular-nums ${
                    d.delta_seconds == null ? 'text-ibm-red-60' : 'text-ibm-green-60'
                  }`}
                >
                  {d.delta_seconds == null ? 'unresolved' : fmtDuration(d.delta_seconds)}
                </span>
              </div>
            ))}
            {!deltas.length && (
              <div className="text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                No PRs with failing scans recorded.
              </div>
            )}
          </div>
        </div>

        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Repo health ranking
          </h2>
          <div className="space-y-2">
            {repos.map((r) => (
              <div key={r.repo_full_name} className="text-[12px]">
                <div className="flex items-center justify-between">
                  <span className="font-mono">{r.repo_full_name}</span>
                  <span className="tabular-nums text-carbon-text-secondary dark:text-ibm-gray-30">
                    {r.scan_count} scans · avg {r.avg_risk}
                  </span>
                </div>
                <div className="mt-1 h-1.5 w-full overflow-hidden border border-carbon-border dark:border-ibm-gray-80">
                  <div
                    className="h-full bg-ibm-red-60"
                    style={{ width: `${Math.min(100, r.avg_risk)}%` }}
                  />
                </div>
              </div>
            ))}
            {!repos.length && (
              <div className="text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                No repos have been scanned yet.
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
