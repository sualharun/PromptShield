import { memo } from 'react'

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
  if (s <= 30) return '#5ec8ff'
  if (s <= 60) return '#ffd86e'
  if (s <= 85) return '#ff9b52'
  return '#ff5b73'
}

function PRScanRow({ scan, threshold = 70, onSelect }) {
  const failed = scan.risk_score >= threshold
  const sha = (scan.commit_sha || '').slice(0, 7)
  return (
    <tr
      onClick={() => onSelect?.(scan.id)}
      className="app-table-row terminal-mono cursor-pointer border-b border-white/8 bg-transparent"
    >
      <td className="px-4 py-4 text-sm text-[#eef5ff]">
        <div className="flex flex-col">
          <span className="font-medium">{scan.repo_full_name || '—'}</span>
          {scan.pr_title && (
            <span className="mt-1 truncate text-[12px] text-[#8da7cd]">
              {scan.pr_title}
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-4 font-mono text-sm text-[#bfd0ef]">
        #{scan.pr_number ?? '—'}
      </td>
      <td className="px-4 py-4 font-mono text-[11px] text-[#8da7cd]">
        {sha || '—'}
      </td>
      <td
        className="px-4 py-4 font-mono text-[18px] font-semibold tabular-nums"
        style={{ color: scoreColor(scan.risk_score) }}
      >
        {scan.risk_score}
      </td>
      <td className="px-4 py-4">
        <span
          className={`inline-flex items-center gap-1.5 border px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide ${
            failed
              ? 'border-[#ff7d8f]/30 bg-[#ff5b73]/10 text-[#ffb7c2]'
              : 'border-[#5ec8ff]/25 bg-[#5ec8ff]/10 text-[#b3eaff]'
          }`}
        >
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: failed ? '#ff5b73' : '#5ec8ff' }}
          />
          {failed ? 'Gate failed' : 'Passing'}
        </span>
      </td>
      <td className="px-4 py-4 text-[12px] text-[#8da7cd]">
        {fmt(scan.created_at)}
      </td>
      <td className="px-4 py-4 text-right">
        {scan.pr_url && (
          <a
            href={scan.pr_url}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="text-[11px] font-medium text-[#8fbcff] hover:text-white"
          >
            GitHub ↗
          </a>
        )}
      </td>
    </tr>
  )
}

export default memo(PRScanRow)
