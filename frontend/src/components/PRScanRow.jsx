import { memo } from 'react'
import { providerMeta } from '../lib/agentAccounts.js'

function fmt(ts) {
  try {
    const d = new Date(ts)
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return ts
  }
}

function scoreColor(s) {
  if (s <= 30) return '#198038'
  if (s <= 60) return '#8a6800'
  if (s <= 85) return '#b8470c'
  return '#a2191f'
}

function ProviderBadge({ provider }) {
  const meta = providerMeta(provider)
  return (
    <span className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] ${meta.tone}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.accent }} />
      {meta.label}
    </span>
  )
}

function PRScanRow({ scan, threshold = 70, onSelect, agentAccount = null }) {
  const failed = scan.risk_score >= threshold
  const sha = (scan.commit_sha || '').slice(0, 7)
  return (
    <tr
      tabIndex={0}
      role="button"
      onClick={() => onSelect?.(scan.id)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect?.(scan.id)
        }
      }}
      className="cursor-pointer border-b border-[#de715d]/18 bg-white transition-colors hover:bg-[#f7f5ef] focus-visible:outline focus-visible:ring-2 focus-visible:ring-[#de715d]/50"
    >
      <td className="px-4 py-3 text-sm text-[#16213e]">
        <div className="flex flex-col">
          <span className="font-medium">{scan.repo_full_name || '—'}</span>
          {scan.pr_title && (
            <span className="mt-0.5 truncate text-[11px] text-[#4b5876]">
              {scan.pr_title}
            </span>
          )}
          {(agentAccount || scan.author_login) && (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {agentAccount && <ProviderBadge provider={agentAccount.provider} />}
              <span className="font-mono text-[11px] text-[#4b5876]">
                @{agentAccount?.githubHandle || scan.author_login}
              </span>
            </div>
          )}
        </div>
      </td>
      <td className="px-4 py-3 font-mono text-sm text-[#4b5876]">
        #{scan.pr_number ?? '—'}
      </td>
      <td className="px-4 py-3 font-mono text-[11px] text-[#4b5876]">
        {sha || '—'}
      </td>
      <td
        className="px-4 py-3 font-mono text-base font-semibold tabular-nums"
        style={{ color: scoreColor(scan.risk_score) }}
      >
        {scan.risk_score}
      </td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center gap-1.5 border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${
            failed
              ? 'border-[#f1b7aa] bg-[#fff1ec] text-[#8f3c2d]'
              : 'border-[#d3d0c1] bg-[#f3f1ea] text-[#58532a]'
          }`}
        >
          <span
            className="h-1.5 w-1.5"
            style={{ background: failed ? '#de715d' : '#58532a' }}
          />
          {failed ? 'Gate failed' : 'Passing'}
        </span>
      </td>
      <td className="px-4 py-3 text-[11px] text-[#4b5876]">
        {fmt(scan.created_at)}
      </td>
      <td className="px-4 py-3 text-right">
        {scan.pr_url && (
          <a
            href={scan.pr_url}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="text-[11px] font-medium text-[#16213e] hover:text-[#de715d]"
          >
            GitHub ↗
          </a>
        )}
      </td>
    </tr>
  )
}

export default memo(PRScanRow)
