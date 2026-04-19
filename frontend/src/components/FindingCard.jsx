import { useState } from 'react'
import SeverityBadge from './SeverityBadge.jsx'

const BORDER_COLOR = {
  critical: '#da1e28',
  high: '#ff832b',
  medium: '#f1c21b',
  low: '#0f62fe',
}

export default function FindingCard({
  finding,
  index = 0,
  onSuggestFix,
  suggesting = false,
  suggestion = '',
  onSuppress,
  suppressing = false,
  repoFullName = null,
}) {
  const [open, setOpen] = useState(false)
  const sev = (finding.severity || 'low').toLowerCase()
  const confidencePct =
    typeof finding.confidence === 'number'
      ? Math.round(finding.confidence * 100)
      : null
  const isSuppressed = !!finding.suppressed

  return (
    <article
      className={`animate-fade-up border border-carbon-border bg-white transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:hover:bg-ibm-gray-80 ${isSuppressed ? 'opacity-60' : ''}`}
      style={{
        borderLeft: `3px solid ${BORDER_COLOR[sev] || BORDER_COLOR.low}`,
        animationDelay: `${index * 30}ms`,
      }}
    >
      <div className="px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={sev} dot />
          <span className="font-mono text-[11px] uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30">
            {finding.type}
          </span>
          {finding.line_number && (
            <span className="font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              · Ln {finding.line_number}
            </span>
          )}
          <div className="ml-auto flex items-center gap-2">
            {finding.cwe && (
              <span className="border border-carbon-border bg-carbon-layer px-1.5 py-0.5 font-mono text-[10px] font-medium text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
                {finding.cwe}
              </span>
            )}
            {finding.owasp && (
              <span className="border border-carbon-border bg-carbon-layer px-1.5 py-0.5 font-mono text-[10px] font-medium text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
                {finding.owasp.split(':')[0]}
              </span>
            )}
            {confidencePct !== null && (
              <span
                title="Detector confidence"
                className="border border-carbon-border bg-white px-1.5 py-0.5 font-mono text-[10px] font-medium text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30"
              >
                {confidencePct}% conf
              </span>
            )}
            <span className="text-[10px] uppercase tracking-wider text-carbon-text-tertiary dark:text-ibm-gray-40">
              {finding.source === 'ai' ? 'AI' : 'Static'}
            </span>
            {isSuppressed && (
              <span
                title="This finding is marked as a false positive and excluded from scoring displays."
                className="border border-ibm-gray-60 bg-ibm-gray-20 px-1.5 py-0.5 font-mono text-[10px] font-medium text-carbon-text-secondary dark:border-ibm-gray-70 dark:bg-ibm-gray-80 dark:text-ibm-gray-30"
              >
                SUPPRESSED
              </span>
            )}
            {finding.detector === 'atlas_vector_search' && finding.match && (
              <span
                title={`Atlas Vector Search matched a known ${finding.match.category || 'attack'} prompt at ${Math.round((finding.match.score || 0) * 100)}% similarity.`}
                className="inline-flex items-center gap-1 border border-[#13aa52] bg-[#13aa52]/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#13aa52]"
              >
                <span aria-hidden>◆</span>
                Atlas · {Math.round((finding.match.score || 0) * 100)}%
              </span>
            )}
          </div>
        </div>

        {finding.detector === 'atlas_vector_search' && finding.match?.text && (
          <div className="mt-3 border-l-2 border-[#13aa52] bg-[#f3fbf6] px-3 py-2 text-[12px] leading-relaxed text-carbon-text-secondary dark:bg-[#0d1f15] dark:text-ibm-gray-30">
            <div className="mb-1 flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#13aa52]">
              <span>
                ◆ Matched corpus prompt
                {finding.match.category ? ` · ${finding.match.category}` : ''}
              </span>
              <span>
                cosine {Math.round((finding.match.score || 0) * 100)}%
              </span>
            </div>
            <div className="font-mono text-[11px] italic text-carbon-text dark:text-ibm-gray-10">
              "{finding.match.text}"
            </div>
            {finding.match.expected && (
              <div className="mt-1 text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Expected outcome: <span className="font-mono">{finding.match.expected}</span>
              </div>
            )}
          </div>
        )}

        <h3 className="mt-3 text-[15px] font-semibold leading-snug text-carbon-text dark:text-ibm-gray-10">
          {finding.title}
        </h3>
        <p className="mt-1 text-sm leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
          {finding.description}
        </p>

        {finding.evidence && (
          <pre className="mt-3 overflow-x-auto bg-ibm-gray-100 px-3 py-2 font-mono text-[11px] text-ibm-gray-10 scrollbar-thin dark:bg-black">
            {finding.evidence}
          </pre>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-4">
          <button
            onClick={() => setOpen((v) => !v)}
            className="inline-flex items-center gap-1 text-[13px] font-medium text-ibm-blue-70 hover:text-ibm-blue-80 dark:text-ibm-blue-30 dark:hover:text-ibm-blue-20"
          >
            <span>{open ? 'Hide remediation' : 'Show remediation'}</span>
            <span className={`transition ${open ? 'rotate-90' : ''}`}>›</span>
          </button>
          {onSuggestFix && (
            <button
              onClick={onSuggestFix}
              disabled={suggesting}
              className="inline-flex items-center gap-2 border border-carbon-border bg-white px-2.5 py-1 text-[12px] font-medium text-carbon-text transition-colors hover:bg-carbon-layer disabled:cursor-not-allowed disabled:opacity-60 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
            >
              {suggesting ? 'Generating fix…' : 'Suggest secure fix'}
            </button>
          )}
          {onSuppress && !isSuppressed && (
            <button
              onClick={() => onSuppress(finding, repoFullName)}
              disabled={suppressing}
              className="inline-flex items-center gap-2 border border-carbon-border bg-white px-2.5 py-1 text-[12px] font-medium text-carbon-text-secondary transition-colors hover:bg-carbon-layer disabled:cursor-not-allowed disabled:opacity-60 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
            >
              {suppressing ? 'Marking…' : 'Mark false positive'}
            </button>
          )}
        </div>

        {open && (
          <div className="mt-3 border-l-2 border-ibm-blue-60 bg-[#1b2637] px-3 py-2 text-sm text-[#c7ddff] animate-fade-in dark:bg-[#1b2637] dark:text-[#c7ddff]">
            <span className="font-semibold">Fix:</span>{' '}
            {finding.remediation || 'No remediation provided.'}
          </div>
        )}

        {suggestion && (
          <div className="mt-3 border-l-2 border-ibm-purple-60 bg-[#271d35] px-3 py-2 text-sm text-[#dcc4ff] animate-fade-in dark:bg-[#271d35] dark:text-[#dcc4ff]">
            <span className="font-semibold">AI fix suggestion:</span> {suggestion}
          </div>
        )}
      </div>
    </article>
  )
}
