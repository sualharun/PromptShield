import { useEffect, useMemo, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

const DEMO_POLICY = `version: 1
min_score: 25
block_if:
  critical: 1
  high: 2
ignore:
  types: ["prompt_length"]
severity_overrides:
  role_confusion: high
`

function Panel({ title, children, actions }) {
  return (
    <div className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
          {title}
        </h3>
        {actions}
      </div>
      {children}
    </div>
  )
}

function Json({ data }) {
  return (
    <pre className="max-h-72 overflow-auto border border-carbon-border bg-carbon-layer p-3 text-[11px] leading-relaxed dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
      {JSON.stringify(data, null, 2)}
    </pre>
  )
}

export default function EnterprisePage() {
  const [scanId, setScanId] = useState('')
  const [loading, setLoading] = useState(false)
  const [policyText, setPolicyText] = useState(DEMO_POLICY)

  const [policyResult, setPolicyResult] = useState(null)
  const [prComment, setPrComment] = useState(null)
  const [brief, setBrief] = useState(null)
  const [replay, setReplay] = useState(null)
  const [benchmarkRun, setBenchmarkRun] = useState(null)
  const [benchHistory, setBenchHistory] = useState(null)
  const [heatmap, setHeatmap] = useState(null)
  const [changes, setChanges] = useState(null)
  const [modelMatrix, setModelMatrix] = useState(null)
  const [auditTrail, setAuditTrail] = useState(null)
  const [ticketResult, setTicketResult] = useState(null)

  useEffect(() => {
    let mounted = true
    const boot = async () => {
      try {
        const r = await fetchWithTimeout('/api/scans')
        if (!r.ok) return
        const scans = await r.json()
        if (mounted && scans?.length) {
          setScanId(String(scans[0].id))
        }
      } catch {
        // ignore
      }
    }
    boot()
    return () => {
      mounted = false
    }
  }, [])

  const canRun = useMemo(() => !!scanId, [scanId])

  const runPolicy = async () => {
    if (!canRun) return
    setLoading(true)
    try {
      const r = await fetchWithTimeout('/api/enterprise/policy/enforce', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: Number(scanId), policy_text: policyText }),
      })
      setPolicyResult(await r.json())
    } finally {
      setLoading(false)
    }
  }

  const runPrComment = async () => {
    if (!canRun) return
    const r = await fetchWithTimeout(`/api/enterprise/pr-comment/${scanId}`)
    setPrComment(await r.json())
  }

  const runBrief = async () => {
    if (!canRun) return
    const r = await fetchWithTimeout(`/api/enterprise/brief/${scanId}`)
    setBrief(await r.json())
  }

  const runReplay = async () => {
    if (!canRun) return
    const r = await fetchWithTimeout(`/api/enterprise/attack-replay/${scanId}`)
    setReplay(await r.json())
  }

  const runBenchmark = async () => {
    const r = await fetchWithTimeout('/api/enterprise/benchmark/run', { method: 'POST' })
    setBenchmarkRun(await r.json())
  }

  const loadBenchHistory = async () => {
    const r = await fetchWithTimeout('/api/enterprise/benchmark/history')
    setBenchHistory(await r.json())
  }

  const loadHeatmap = async () => {
    const r = await fetchWithTimeout('/api/enterprise/org/heatmap')
    setHeatmap(await r.json())
  }

  const runChanges = async () => {
    if (!canRun) return
    const r = await fetchWithTimeout(`/api/enterprise/changes/${scanId}`)
    setChanges(await r.json())
  }

  const runTicket = async () => {
    const r = await fetchWithTimeout('/api/enterprise/integration/ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        summary: `PromptShield critical finding from scan #${scanId || 'n/a'}`,
        severity: 'high',
        repo_full_name: 'demo/repo',
      }),
    })
    setTicketResult(await r.json())
  }

  const runModelMatrix = async () => {
    const r = await fetchWithTimeout('/api/enterprise/model-matrix')
    setModelMatrix(await r.json())
  }

  const runAuditTrail = async () => {
    const r = await fetchWithTimeout('/api/enterprise/audit-trail')
    setAuditTrail(await r.json())
  }

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8 space-y-4">
      <div className="border border-carbon-border bg-carbon-layer p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
        <div className="grid gap-3 md:grid-cols-[1fr,220px]">
          <div>
            <p className="text-[11px] uppercase tracking-[0.1em] text-ibm-blue-60">Enterprise showcase</p>
            <h1 className="text-2xl font-light">Governance + DevEx + Executive Readouts</h1>
            <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
              Single-page demo surface covering policy-as-code, PR workflows, benchmark quality, multi-tenant heatmap,
              integrations, model matrix, and immutable audit trail.
            </p>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[11px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Scan ID</label>
            <input
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              className="border border-carbon-border bg-white px-2 py-1.5 text-sm dark:border-ibm-gray-80 dark:bg-ibm-gray-90"
              placeholder="latest scan id"
            />
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Policy-as-Code + Enforcement Score"
          actions={<button onClick={runPolicy} disabled={!canRun || loading} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Simulate policy change</button>}
        >
          <textarea
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
            className="mb-3 h-40 w-full border border-carbon-border bg-carbon-layer p-2 font-mono text-xs dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
          />
          {policyResult && <Json data={policyResult} />}
        </Panel>

        <Panel
          title="Auto PR Security Comment + Suggested Patch"
          actions={<button onClick={runPrComment} disabled={!canRun} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Generate comment</button>}
        >
          {prComment ? <Json data={prComment} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Generate a PR-ready security comment and patch hint.</p>}
        </Panel>

        <Panel
          title="Executive Risk Brief"
          actions={<div className="flex items-center gap-2"><button onClick={runBrief} disabled={!canRun} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Generate</button>{canRun && <a href={`/api/enterprise/brief/${scanId}.pdf`} className="border border-carbon-border px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em]">PDF</a>}</div>}
        >
          {brief ? <Json data={brief} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">CISO-style posture summary + trend + SLA + risk acceptance.</p>}
        </Panel>

        <Panel
          title="Attack Replay Timeline"
          actions={<button onClick={runReplay} disabled={!canRun} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Build replay</button>}
        >
          {replay ? <Json data={replay} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Timestamped entry to propagation to impact timeline with confidence.</p>}
        </Panel>

        <Panel
          title="Benchmark Mode"
          actions={<div className="flex gap-2"><button onClick={runBenchmark} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Run benchmark</button><button onClick={loadBenchHistory} className="border border-carbon-border px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em]">History</button></div>}
        >
          {benchmarkRun && <Json data={benchmarkRun} />}
          {benchHistory && <div className="mt-2"><Json data={benchHistory} /></div>}
          {!benchmarkRun && !benchHistory && <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Precision/recall/F1 with regression tracking.</p>}
        </Panel>

        <Panel
          title="Org Multi-Tenant Heatmap"
          actions={<button onClick={loadHeatmap} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Load heatmap</button>}
        >
          {heatmap ? <Json data={heatmap} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Cross-repo risk concentration and scan volume.</p>}
        </Panel>

        <Panel
          title="Live Changes Since Last Scan"
          actions={<button onClick={runChanges} disabled={!canRun} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Diff scan</button>}
        >
          {changes ? <Json data={changes} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Added / resolved / persistent findings with score shift.</p>}
        </Panel>

        <Panel
          title="Integration Story (Jira Ticket)"
          actions={<button onClick={runTicket} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Create ticket</button>}
        >
          {ticketResult ? <Json data={ticketResult} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Create ticket event from critical finding metadata.</p>}
        </Panel>

        <Panel
          title="Model-Agnostic Matrix"
          actions={<button onClick={runModelMatrix} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Load providers</button>}
        >
          {modelMatrix ? <Json data={modelMatrix} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Provider coverage view, including IBM-ready adapter row.</p>}
        </Panel>

        <Panel
          title="Trust + Audit Trail"
          actions={<button onClick={runAuditTrail} className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-white">Load audit events</button>}
        >
          {auditTrail ? <Json data={auditTrail} /> : <p className="text-sm text-carbon-text-secondary dark:text-ibm-gray-30">Immutable timeline of scan, suppression, and risk-acceptance actions.</p>}
        </Panel>
      </div>
    </div>
  )
}
