import { useMemo, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'
import RiskGauge from '../components/RiskGauge.jsx'
import FindingCard from '../components/FindingCard.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import FindingsToolbar from '../components/FindingsToolbar.jsx'
import ScoreBreakdown from '../components/ScoreBreakdown.jsx'
import DependencyGraph from '../components/DependencyGraph.jsx'
import AttackerSimulationPanel from '../components/AttackerSimulationPanel.jsx'
import SimilarScansPanel from '../components/SimilarScansPanel.jsx'
import PanelErrorBoundary from '../components/PanelErrorBoundary.jsx'
import { CategoryRadar, SeverityBar, TrendLine } from '../components/Charts.jsx'

const ALL_SEV = ['critical', 'high', 'medium', 'low']

function fmt(ts) {
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

export default function ReportPage({ report, history = [], onNewScan }) {
  const [activePanel, setActivePanel] = useState('findings')
  const [activeSeverities, setActiveSeverities] = useState(ALL_SEV)
  const [query, setQuery] = useState('')
  const [suggestions, setSuggestions] = useState({})
  const [suggesting, setSuggesting] = useState({})
  const [suppressedSigs, setSuppressedSigs] = useState(new Set())
  const [suppressing, setSuppressing] = useState({})

  if (!report) return null

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 }
    report.findings.forEach((f) => {
      const s = (f.severity || 'low').toLowerCase()
      if (c[s] !== undefined) c[s] += 1
    })
    return c
  }, [report])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return report.findings.filter((f) => {
      if (!activeSeverities.includes((f.severity || 'low').toLowerCase()))
        return false
      if (!q) return true
      return (
        (f.title || '').toLowerCase().includes(q) ||
        (f.type || '').toLowerCase().includes(q) ||
        (f.evidence || '').toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
      )
    })
  }, [report, activeSeverities, query])

  const grouped = useMemo(() => {
    const order = ['critical', 'high', 'medium', 'low']
    const buckets = {
      critical: [],
      high: [],
      medium: [],
      low: [],
    }
    filtered.forEach((f) => {
      const sev = (f.severity || 'low').toLowerCase()
      if (buckets[sev]) buckets[sev].push(f)
      else buckets.low.push(f)
    })
    return order
      .map((sev) => ({ sev, items: buckets[sev] }))
      .filter((g) => g.items.length > 0)
  }, [filtered])

  const toggleSeverity = (sev) =>
    setActiveSeverities((curr) =>
      curr.includes(sev) ? curr.filter((s) => s !== sev) : [...curr, sev]
    )

  const clearFilters = () => {
    setActiveSeverities(ALL_SEV)
    setQuery('')
  }

  const requestSuggestion = async (finding, idx) => {
    const key = `${idx}-${finding.type}`
    setSuggesting((s) => ({ ...s, [key]: true }))
    try {
      const r = await fetchWithTimeout('/api/findings/suggest-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, code_context: report.input_text }),
      })
      if (!r.ok) throw new Error('Failed to generate fix suggestion')
      const data = await r.json()
      setSuggestions((s) => ({ ...s, [key]: data.suggested_fix || '' }))
    } catch {
      setSuggestions((s) => ({
        ...s,
        [key]: 'Unable to generate AI suggestion right now. Use the remediation guidance above.',
      }))
    } finally {
      setSuggesting((s) => ({ ...s, [key]: false }))
    }
  }

  const suppressFinding = async (finding, repoFullName) => {
    const key = finding.signature || `${finding.type}-${finding.title}`
    setSuppressing((s) => ({ ...s, [key]: true }))
    try {
      const r = await fetchWithTimeout('/api/suppressions', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, repo_full_name: repoFullName || null }),
      })
      if (!r.ok) throw new Error('suppress failed')
      const row = await r.json()
      setSuppressedSigs((curr) => {
        const next = new Set(curr)
        next.add(row.signature)
        return next
      })
    } catch {
      // swallow — user can retry
    } finally {
      setSuppressing((s) => ({ ...s, [key]: false }))
    }
  }

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ibm-blue-70 dark:text-ibm-blue-40">
            Scan report · #{report.id}
          </p>
          <h1 className="mt-1 font-light text-3xl text-carbon-text dark:text-ibm-gray-10">
            Vulnerability assessment
          </h1>
          <p className="mt-1 text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            {fmt(report.created_at)} · {report.static_count} static ·{' '}
            {report.ai_count} AI
          </p>
        </div>
        <button
          onClick={onNewScan}
          className="border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
        >
          New scan
        </button>
      </div>

      <section className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-[260px,1fr] dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="flex items-center justify-center bg-white p-6 dark:bg-ibm-gray-90">
          <RiskGauge score={report.risk_score} size={180} />
        </div>
        <div className="grid gap-px bg-carbon-border md:grid-cols-4 dark:bg-ibm-gray-80">
          {[
            { label: 'Total findings', value: report.total_count, mono: true },
            {
              label: 'Critical',
              value: counts.critical,
              color: '#a2191f',
              mono: true,
            },
            {
              label: 'High',
              value: counts.high,
              color: '#b8470c',
              mono: true,
            },
            {
              label: 'Medium + Low',
              value: counts.medium + counts.low,
              color: '#525252',
              mono: true,
            },
          ].map((kpi) => (
            <div key={kpi.label} className="bg-white px-5 py-5 dark:bg-ibm-gray-90">
              <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                {kpi.label}
              </div>
              <div
                className="mt-2 font-light text-3xl tabular-nums"
                style={{ color: kpi.color || 'var(--carbon-text)' }}
              >
                {kpi.value}
              </div>
            </div>
          ))}
          <div className="col-span-2 bg-white px-5 py-4 md:col-span-4 dark:bg-ibm-gray-90">
            <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Severity breakdown
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {ALL_SEV.map((s) => (
                <SeverityBadge key={s} severity={s} count={counts[s]} dot />
              ))}
            </div>
          </div>
        </div>
      </section>

      <ScoreBreakdown breakdown={report.score_breakdown} />

      <section className="mt-8">
        <div className="inline-flex border border-carbon-border bg-white text-[11px] font-semibold uppercase tracking-[0.08em] dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <button
            className={`px-3 py-2 transition-colors ${activePanel === 'findings' ? 'bg-carbon-layer text-carbon-text dark:bg-ibm-gray-100 dark:text-ibm-gray-10' : 'text-carbon-text-tertiary dark:text-ibm-gray-40'}`}
            onClick={() => setActivePanel('findings')}
          >
            Findings
          </button>
          <button
            className={`border-l border-carbon-border px-3 py-2 transition-colors dark:border-ibm-gray-80 ${activePanel === 'graph' ? 'bg-carbon-layer text-carbon-text dark:bg-ibm-gray-100 dark:text-ibm-gray-10' : 'text-carbon-text-tertiary dark:text-ibm-gray-40'}`}
            onClick={() => setActivePanel('graph')}
          >
            Dependency graph
          </button>
          <button
            className={`border-l border-carbon-border px-3 py-2 transition-colors dark:border-ibm-gray-80 ${activePanel === 'attacker' ? 'bg-carbon-layer text-carbon-text dark:bg-ibm-gray-100 dark:text-ibm-gray-10' : 'text-carbon-text-tertiary dark:text-ibm-gray-40'}`}
            onClick={() => setActivePanel('attacker')}
          >
            Attacker mode
          </button>
          <button
            className={`border-l border-carbon-border px-3 py-2 transition-colors dark:border-ibm-gray-80 ${activePanel === 'similar' ? 'bg-carbon-layer text-carbon-text dark:bg-ibm-gray-100 dark:text-ibm-gray-10' : 'text-carbon-text-tertiary dark:text-ibm-gray-40'}`}
            onClick={() => setActivePanel('similar')}
            title="Atlas Vector Search"
          >
            <span className="text-[#13aa52]">◆</span> Similar past scans
          </button>
        </div>
      </section>

      {activePanel === 'findings' && (
      <section className="mt-6">
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Findings
          </h2>
          <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Sorted by severity, then confidence
          </span>
        </div>

        <FindingsToolbar
          counts={counts}
          activeSeverities={activeSeverities}
          onToggleSeverity={toggleSeverity}
          onClear={clearFilters}
          query={query}
          onQuery={setQuery}
          total={report.findings.length}
          shown={filtered.length}
        />

        {report.findings.length === 0 ? (
          <div className="mt-3 border border-ibm-green-60 bg-[#defbe6] px-5 py-6 text-center dark:bg-ibm-green-60/20">
            <p className="text-base font-semibold text-ibm-green-60 dark:text-ibm-green-50">
              No vulnerabilities detected
            </p>
            <p className="mt-1 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
              Static and AI passes both came back clean.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="mt-3 border border-carbon-border bg-carbon-layer px-5 py-6 text-center text-sm text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
            No findings match the current filters.
          </div>
        ) : (
          <div className="mt-3 space-y-6">
            {grouped.map((group) => (
              <div key={group.sev} className="border border-carbon-border bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
                <div className="flex items-center justify-between border-b border-carbon-border px-4 py-2 dark:border-ibm-gray-80">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={group.sev} count={group.items.length} dot />
                    <span className="text-[11px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                      severity group
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                    {group.items.length} item{group.items.length === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="space-y-2 p-2">
                  {group.items.map((f, i) => {
                    const reportIndex = report.findings.indexOf(f)
                    const overlayed = suppressedSigs.has(f.signature)
                      ? { ...f, suppressed: true }
                      : f
                    const supKey = f.signature || `${f.type}-${f.title}`
                    return (
                      <FindingCard
                        key={`${group.sev}-${f.type}-${reportIndex}-${i}`}
                        finding={overlayed}
                        index={i}
                        onSuggestFix={() => requestSuggestion(f, reportIndex)}
                        suggesting={!!suggesting[`${reportIndex}-${f.type}`]}
                        suggestion={suggestions[`${reportIndex}-${f.type}`] || ''}
                        onSuppress={suppressFinding}
                        suppressing={!!suppressing[supKey]}
                      />
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
      )}

      {activePanel === 'graph' && (
        <section className="mt-6">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Dependency graph analysis
            </h2>
            <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Hidden supply-chain paths and blast radius
            </span>
          </div>
          <PanelErrorBoundary>
            <DependencyGraph scanId={report.id} />
          </PanelErrorBoundary>
        </section>
      )}

      {activePanel === 'attacker' && (
        <section className="mt-6">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Attacker simulation
            </h2>
            <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Proactive exploit-path analysis from this report
            </span>
          </div>
          <AttackerSimulationPanel scanId={report.id} />
        </section>
      )}

      {activePanel === 'similar' && (
        <section className="mt-6">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Semantically similar prompts
            </h2>
            <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              MongoDB Atlas Vector Search · top-5 cosine
            </span>
          </div>
          <PanelErrorBoundary>
            <SimilarScansPanel scanId={report.id} />
          </PanelErrorBoundary>
        </section>
      )}

      <section className="mt-10">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Analytics
        </h2>
        <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
          <div className="bg-white p-5 dark:bg-ibm-gray-90">
            <h3 className="mb-2 text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">
              Findings by severity
            </h3>
            <SeverityBar findings={report.findings} />
          </div>
          <div className="bg-white p-5 dark:bg-ibm-gray-90">
            <h3 className="mb-2 text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">
              Vulnerability category radar
            </h3>
            <CategoryRadar findings={report.findings} />
          </div>
          {history.length > 1 && (
            <div className="bg-white p-5 md:col-span-2 dark:bg-ibm-gray-90">
              <h3 className="mb-2 text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">
                Risk score trend
              </h3>
              <TrendLine scans={history} />
            </div>
          )}
        </div>
      </section>

      <section className="mt-10">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Scanned input
        </h2>
        <pre className="max-h-96 overflow-auto border border-carbon-border bg-ibm-gray-100 p-4 font-mono text-[12px] leading-relaxed text-ibm-gray-10 scrollbar-thin dark:border-ibm-gray-80">
          {report.input_text}
        </pre>
        <p className="mt-2 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Secrets and PII are redacted before persistence.
        </p>
      </section>
    </div>
  )
}
