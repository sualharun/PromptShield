import { useMemo, useState } from 'react'
import {
  AlertTriangle,
  ChevronDown,
  Code2,
  Cpu,
  Shield,
  Zap,
} from 'lucide-react'

/**
 * AgentSecurityPanel — focused view of agent-related findings (the agentic
 * security pivot).  Filters the full finding list down to:
 *   - James's analyzer types (AGENT_*, source=agent_analysis)
 *   - PromptShield's static + dataflow agentic types (TOOL_*, DANGEROUS_TOOL_*,
 *     LLM_OUTPUT_*, RAG_UNSANITIZED_CONTEXT, DANGEROUS_SINK,
 *     UNVALIDATED_FUNCTION_PARAM_TO_SINK)
 *
 * Renders in the light Carbon theme to match the rest of ReportPage.
 */
export function AgentSecurityPanel({ findings = [] }) {
  const [expandedFinding, setExpandedFinding] = useState(null)

  const agentFindings = useMemo(
    () =>
      findings.filter((f) => {
        const t = f.type || ''
        if (f.source === 'agent_analysis') return true
        if (t.startsWith('AGENT_')) return true
        if (t.startsWith('TOOL_')) return true
        if (t.startsWith('DANGEROUS_TOOL')) return true
        if (t === 'DANGEROUS_SINK') return true
        if (t === 'UNVALIDATED_FUNCTION_PARAM_TO_SINK') return true
        if (t === 'DATAFLOW_INJECTION') return true
        if (t.startsWith('LLM_OUTPUT_')) return true
        if (t === 'RAG_UNSANITIZED_CONTEXT') return true
        return false
      }),
    [findings]
  )

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 }
    agentFindings.forEach((f) => {
      const s = (f.severity || 'low').toLowerCase()
      if (c[s] !== undefined) c[s] += 1
    })
    return c
  }, [agentFindings])

  const typeCounts = useMemo(() => {
    const m = {}
    agentFindings.forEach((f) => {
      m[f.type] = (m[f.type] || 0) + 1
    })
    return Object.entries(m).sort((a, b) => b[1] - a[1])
  }, [agentFindings])

  if (agentFindings.length === 0) {
    return (
      <div className="border-l-4 border-ibm-green-60 border-y border-r border-carbon-border bg-[#defbe6] px-5 py-4 dark:border-r-ibm-gray-80 dark:border-y-ibm-gray-80 dark:bg-ibm-green-60/15">
        <div className="flex items-center gap-3">
          <Shield className="h-5 w-5 text-ibm-green-60 dark:text-ibm-green-50" />
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ibm-green-60">
              Agent security · clean
            </p>
            <p className="mt-0.5 text-[14px] text-carbon-text dark:text-ibm-gray-10">
              No exposed-tool, dataflow, or unsafe-output findings detected on
              this scan.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* KPI strip */}
      <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <KpiTile
          label="Agent issues"
          value={agentFindings.length}
          accent="#0f62fe"
          icon={<Cpu className="h-4 w-4" />}
        />
        <KpiTile label="Critical" value={counts.critical} accent="#a2191f" />
        <KpiTile label="High" value={counts.high} accent="#b8470c" />
        <KpiTile label="Medium" value={counts.medium} accent="#8a6800" />
        <KpiTile label="Low" value={counts.low} accent="#525252" />
      </div>

      {/* Findings */}
      <div className="border border-carbon-border bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
        <div className="flex items-center justify-between border-b border-carbon-border px-4 py-2 dark:border-ibm-gray-80">
          <div className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-ibm-blue-70 dark:text-ibm-blue-30" />
            <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
              AI Agent function security
            </span>
          </div>
          <span className="font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            OWASP LLM06 · LLM05 · LLM01
          </span>
        </div>

        <div className="space-y-2 p-2">
          {agentFindings.map((finding, idx) => (
            <AgentFindingCard
              key={`${finding.type}-${idx}`}
              finding={finding}
              expanded={expandedFinding === idx}
              onToggle={() =>
                setExpandedFinding(expandedFinding === idx ? null : idx)
              }
            />
          ))}
        </div>
      </div>

      {/* Type histogram */}
      {typeCounts.length > 0 && (
        <div className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Findings by type
            </h4>
            <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              {agentFindings.length} total
            </span>
          </div>
          <div className="space-y-1.5">
            {typeCounts.map(([type, count]) => (
              <div
                key={type}
                className="flex items-center justify-between border-b border-carbon-border/50 pb-1.5 last:border-b-0 last:pb-0 dark:border-ibm-gray-80/50"
              >
                <code className="text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
                  {type}
                </code>
                <span className="font-mono text-[11px] font-semibold text-carbon-text dark:text-ibm-gray-10">
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function KpiTile({ label, value, accent, icon }) {
  return (
    <div className="flex items-start justify-between bg-white px-4 py-4 dark:bg-ibm-gray-90">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          {label}
        </div>
        <div
          className="mt-1.5 font-light text-2xl tabular-nums"
          style={{ color: accent }}
        >
          {value}
        </div>
      </div>
      {icon && <div className="text-carbon-text-tertiary dark:text-ibm-gray-40">{icon}</div>}
    </div>
  )
}

const SEV_TONE = {
  critical: {
    bar: '#a2191f',
    bg: '#fff1f1',
    text: '#a2191f',
    icon: <AlertTriangle className="h-4 w-4" style={{ color: '#a2191f' }} />,
  },
  high: {
    bar: '#b8470c',
    bg: '#fff8f1',
    text: '#b8470c',
    icon: <AlertTriangle className="h-4 w-4" style={{ color: '#b8470c' }} />,
  },
  medium: {
    bar: '#8a6800',
    bg: '#fff8e1',
    text: '#8a6800',
    icon: <Zap className="h-4 w-4" style={{ color: '#8a6800' }} />,
  },
  low: {
    bar: '#525252',
    bg: '#f4f4f4',
    text: '#525252',
    icon: <Shield className="h-4 w-4" style={{ color: '#525252' }} />,
  },
}

function AgentFindingCard({ finding, expanded, onToggle }) {
  const sev = (finding.severity || 'low').toLowerCase()
  const tone = SEV_TONE[sev] || SEV_TONE.low
  const description = finding.description || ''
  const remediation = finding.remediation || ''

  return (
    <div
      className="border-l-4 border-y border-r border-carbon-border bg-white dark:border-y-ibm-gray-80 dark:border-r-ibm-gray-80 dark:bg-ibm-gray-90"
      style={{ borderLeftColor: tone.bar }}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-carbon-layer dark:hover:bg-ibm-gray-100"
      >
        <div className="flex flex-1 items-start gap-3">
          {tone.icon}
          <div className="flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="text-[14px] font-semibold text-carbon-text dark:text-ibm-gray-10">
                {finding.title || finding.type}
              </h4>
              <span
                className="font-mono text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: tone.text }}
              >
                {sev}
              </span>
            </div>
            {description && (
              <p className="mt-1 text-[12.5px] leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
                {description.split('\n')[0]}
              </p>
            )}
            <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              <code className="font-mono">{finding.type}</code>
              {finding.line_number != null && <span>line {finding.line_number}</span>}
              {finding.cwe && <span className="font-mono">{finding.cwe}</span>}
              {finding.owasp && <span className="font-mono">{finding.owasp}</span>}
              {finding.agent_function && (
                <span>
                  fn <code className="font-mono">{finding.agent_function}</code>
                </span>
              )}
              {finding.agent_sink && (
                <span>
                  sink <code className="font-mono">{finding.agent_sink}</code>
                </span>
              )}
              {finding.confidence != null && (
                <span>
                  confidence{' '}
                  <span className="font-mono">
                    {Math.round((finding.confidence || 0) * 100)}%
                  </span>
                </span>
              )}
            </div>
          </div>
        </div>
        <ChevronDown
          className={`h-4 w-4 flex-shrink-0 text-carbon-text-tertiary transition-transform dark:text-ibm-gray-40 ${
            expanded ? 'rotate-180' : ''
          }`}
        />
      </button>

      {expanded && (
        <div className="space-y-3 border-t border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          {finding.evidence && (
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Evidence
              </p>
              <pre className="overflow-x-auto border border-carbon-border bg-ibm-gray-100 p-2 font-mono text-[11.5px] leading-relaxed text-ibm-gray-10 dark:border-ibm-gray-80">
                {finding.evidence}
              </pre>
            </div>
          )}

          {description && description.includes('\n') && (
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Details
              </p>
              <p className="whitespace-pre-wrap text-[12.5px] leading-relaxed text-carbon-text dark:text-ibm-gray-10">
                {description}
              </p>
            </div>
          )}

          {remediation && (
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Remediation
              </p>
              <div
                className="border-l-4 px-3 py-2 text-[12.5px] leading-relaxed"
                style={{ borderColor: tone.bar, background: tone.bg, color: '#1c1c1c' }}
              >
                {remediation}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default AgentSecurityPanel
