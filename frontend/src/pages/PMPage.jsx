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

function SectionHeader({ title, body }) {
  return (
    <div className="mb-3">
      <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#8aa6d2]">
        {title}
      </h2>
      {body && <p className="mt-2 text-[12px] text-[#8da7cd]">{body}</p>}
    </div>
  )
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
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="carbon-progress" />
      </div>
    )
  }

  if (!authorized) {
    return (
      <div className="mx-auto w-full max-w-4xl px-6 py-16">
        <p className="app-section-label text-[11px] font-semibold">Product-manager view</p>
        <h1 className="mt-3 font-display text-4xl text-white">Sign in to view PM analytics</h1>
        <p className="mt-3 max-w-2xl text-[14px] leading-relaxed text-[#9bb2d6]">
          The PM dashboard shows author leaderboards, blocked PRs, and remediation deltas.
          It requires a PM or admin role.
        </p>
        <button onClick={onSignIn} className="app-primary-button mt-6 px-4 py-2 text-sm font-medium">
          Sign in
        </button>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="carbon-progress" />
        <p className="mt-3 text-sm text-[#8da7cd]">Loading PM analytics…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mx-auto w-full max-w-7xl px-6 py-10">
        <div className="app-panel border-l-4 border-l-[#ff5b73] px-4 py-3 text-sm text-[#ffd5dc]">
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
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      <div className="mb-6">
        <p className="app-section-label text-[11px] font-semibold">
          Product-manager view
        </p>
        <h1 className="mt-3 font-display text-5xl leading-[0.98] tracking-[-0.05em] text-white">
          Who ships risky code
        </h1>
        <p className="mt-3 max-w-2xl text-[14px] leading-relaxed text-[#9bb2d6]">
          Aggregated from GitHub PR scans. Gate threshold ={' '}
          <span className="font-mono text-[#dbe8ff]">{data?.gate_threshold ?? '—'}</span>.
        </p>
      </div>

      <section className="app-panel">
        <div className="border-b border-white/10 px-4 py-3">
          <SectionHeader title="Authors by gate failures" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/8">
                {['Author', 'Scans', 'Avg risk', 'Gate failures', 'Last scan'].map((header) => (
                  <th
                    key={header}
                    className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-[#8aa6d2]"
                  >
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {byAuthor.map((author) => (
                <tr key={author.author_login} className="app-table-row border-b border-white/8">
                  <td className="px-4 py-2 font-mono text-[12px] text-[#eef5ff]">{author.author_login}</td>
                  <td className="px-4 py-2 text-[12px] tabular-nums text-[#bfd0ef]">{author.scan_count}</td>
                  <td className="px-4 py-2 text-[12px] tabular-nums text-[#bfd0ef]">{author.avg_risk}</td>
                  <td
                    className={`px-4 py-2 text-[12px] tabular-nums ${
                      author.gate_failures > 0 ? 'text-[#ff9cab]' : 'text-[#98e0ff]'
                    }`}
                  >
                    {author.gate_failures}
                  </td>
                  <td className="px-4 py-2 text-[12px] text-[#8da7cd]">
                    {fmtDate(author.last_scan_at)}
                  </td>
                </tr>
              ))}
              {!byAuthor.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-5 text-sm text-[#8da7cd]">
                    No GitHub PR scans with attributable authors yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="app-panel mt-6">
        <div className="border-b border-white/10 px-4 py-3">
          <SectionHeader title="Recently blocked PRs" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/8">
                {['Repo', 'PR', 'Title', 'Score', 'Author', 'Scanned'].map((header) => (
                  <th
                    key={header}
                    className="px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-[#8aa6d2]"
                  >
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {blocked.map((row) => (
                <tr key={row.scan_id} className="app-table-row border-b border-white/8">
                  <td className="px-4 py-2 font-mono text-[12px] text-[#eef5ff]">
                    {row.repo_full_name || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px]">
                    {row.pr_url ? (
                      <a
                        href={row.pr_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[#8fbcff] hover:text-white"
                      >
                        #{row.pr_number}
                      </a>
                    ) : (
                      `#${row.pr_number ?? '—'}`
                    )}
                  </td>
                  <td className="max-w-xs truncate px-4 py-2 text-[12px] text-[#bfd0ef]">
                    {row.pr_title || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px] font-semibold tabular-nums text-[#ff9cab]">
                    {row.risk_score}
                  </td>
                  <td className="px-4 py-2 font-mono text-[12px] text-[#eef5ff]">
                    {row.author_login || '—'}
                  </td>
                  <td className="px-4 py-2 text-[12px] text-[#8da7cd]">
                    {fmtDate(row.created_at)}
                  </td>
                </tr>
              ))}
              {!blocked.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-5 text-sm text-[#8da7cd]">
                    No PRs have crossed the gate yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-6 grid gap-6 md:grid-cols-2">
        <div className="app-panel p-5">
          <SectionHeader
            title="Remediation deltas"
            body="Time between a PR's first failing scan and its first passing scan."
          />
          <div className="space-y-1">
            {deltas.map((delta) => (
              <div
                key={`${delta.repo_full_name}-${delta.pr_number}`}
                className="flex items-center justify-between border-b border-white/8 py-2 text-[12px] last:border-0"
              >
                <span className="font-mono text-[#eef5ff]">
                  {delta.repo_full_name}#{delta.pr_number}
                </span>
                <span
                  className={`tabular-nums ${
                    delta.delta_seconds == null ? 'text-[#ff9cab]' : 'text-[#98e0ff]'
                  }`}
                >
                  {delta.delta_seconds == null ? 'unresolved' : fmtDuration(delta.delta_seconds)}
                </span>
              </div>
            ))}
            {!deltas.length && <div className="text-[12px] text-[#8da7cd]">No PRs with failing scans recorded.</div>}
          </div>
        </div>

        <div className="app-panel p-5">
          <SectionHeader title="Repo health ranking" />
          <div className="space-y-3">
            {repos.map((repo) => (
              <div key={repo.repo_full_name} className="text-[12px]">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[#eef5ff]">{repo.repo_full_name}</span>
                  <span className="tabular-nums text-[#8da7cd]">
                    {repo.scan_count} scans · avg {repo.avg_risk}
                  </span>
                </div>
                <div className="mt-1 h-2 w-full overflow-hidden rounded-full border border-white/8">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.min(100, repo.avg_risk)}%`,
                      background: 'linear-gradient(90deg, #5ec8ff 0%, #5ea8ff 55%, #ff9b52 100%)',
                    }}
                  />
                </div>
              </div>
            ))}
            {!repos.length && <div className="text-[12px] text-[#8da7cd]">No repos have been scanned yet.</div>}
          </div>
        </div>
      </section>
    </div>
  )
}
