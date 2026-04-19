import React, { useState } from 'react'
import { AlertTriangle, Code2, Shield, Zap, ChevronDown } from 'lucide-react'

export function AgentSecurityPanel({ findings = [], language = 'python' }) {
  const [expandedFinding, setExpandedFinding] = useState(null)

  // Filter findings to only agent-related ones
  const agentFindings = findings.filter(f => 
    f.type?.includes('AGENT_') || f.source === 'agent_analysis'
  )

  if (agentFindings.length === 0) {
    return (
      <div className="rounded-lg border border-green-500/30 bg-green-500/5 p-6">
        <div className="flex items-center gap-3 text-green-400">
          <Shield className="h-5 w-5" />
          <span>No agent security issues detected</span>
        </div>
      </div>
    )
  }

  const severityColors = {
    critical: 'bg-red-500/10 border-red-500/30 text-red-400',
    high: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    medium: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    low: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
  }

  const severityIcons = {
    critical: <AlertTriangle className="h-5 w-5 text-red-400" />,
    high: <AlertTriangle className="h-5 w-5 text-orange-400" />,
    medium: <Zap className="h-5 w-5 text-yellow-400" />,
    low: <Shield className="h-5 w-5 text-blue-300" />,
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 border-b border-white/10 pb-3">
        <Code2 className="h-5 w-5 text-purple-400" />
        <h3 className="text-sm font-semibold text-white">AI Agent Function Security</h3>
        <span className="ml-auto rounded bg-red-500/20 px-2 py-1 text-xs text-red-400">
          {agentFindings.length} issue{agentFindings.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="space-y-3">
        {agentFindings.map((finding, idx) => (
          <div
            key={idx}
            className={`rounded-lg border p-4 cursor-pointer transition-all ${
              severityColors[finding.severity] || severityColors.medium
            }`}
            onClick={() => setExpandedFinding(expandedFinding === idx ? null : idx)}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3 flex-1">
                {severityIcons[finding.severity]}
                <div className="flex-1">
                  <h4 className="font-semibold text-white">{finding.title}</h4>
                  <p className="text-xs mt-1 opacity-75">{finding.description?.split('\n')[0]}</p>
                  
                  {/* Metadata row */}
                  <div className="flex gap-4 mt-2 text-xs opacity-60">
                    {finding.line_number && <span>Line {finding.line_number}</span>}
                    {finding.cwe && <span className="font-mono">{finding.cwe}</span>}
                    {finding.agent_function && <span>Function: <code>{finding.agent_function}</code></span>}
                    {finding.agent_sink && <span>Sink: <code>{finding.agent_sink}</code></span>}
                  </div>
                </div>
              </div>
              <ChevronDown
                className={`h-4 w-4 flex-shrink-0 transition-transform ${
                  expandedFinding === idx ? 'rotate-180' : ''
                }`}
              />
            </div>

            {/* Expanded details */}
            {expandedFinding === idx && (
              <div className="mt-4 space-y-3 border-t border-current opacity-75 pt-3">
                {finding.evidence && (
                  <div>
                    <p className="text-xs font-semibold mb-1">Evidence</p>
                    <code className="block text-xs bg-black/30 p-2 rounded overflow-x-auto">
                      {finding.evidence}
                    </code>
                  </div>
                )}

                {finding.description && finding.description.includes('\n') && (
                  <div>
                    <p className="text-xs font-semibold mb-1">Details</p>
                    <p className="text-xs whitespace-pre-wrap">{finding.description}</p>
                  </div>
                )}

                {finding.remediation && (
                  <div>
                    <p className="text-xs font-semibold mb-1">Remediation</p>
                    <div className="text-xs whitespace-pre-wrap bg-black/30 p-2 rounded">
                      {finding.remediation}
                    </div>
                  </div>
                )}

                {finding.owasp && (
                  <div className="flex gap-2 flex-wrap">
                    {finding.owasp.split(',').map(tag => (
                      <span
                        key={tag}
                        className="text-xs px-2 py-1 rounded bg-black/40 border border-current/30"
                      >
                        {tag.trim()}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Summary by type */}
      <div className="mt-4 space-y-2 text-xs border-t border-white/10 pt-3">
        {(() => {
          const typeCounts = {}
          agentFindings.forEach(f => {
            typeCounts[f.type] = (typeCounts[f.type] || 0) + 1
          })
          return Object.entries(typeCounts).map(([type, count]) => (
            <div key={type} className="flex justify-between opacity-60">
              <span>{type}</span>
              <span className="font-semibold">{count}</span>
            </div>
          ))
        })()}
      </div>
    </div>
  )
}

export default AgentSecurityPanel
