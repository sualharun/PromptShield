import { useEffect, useState } from 'react'
import { fetchWithTimeout, asNetworkErrorMessage } from '../lib/fetchWithTimeout.js'

export default function AttackerSimulationPanel({ scanId }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [data, setData] = useState(null)

  const runSimulation = async () => {
    if (!scanId || loading) return
    setLoading(true)
    setError('')
    try {
      const r = await fetchWithTimeout(`/api/attacker-simulate/${scanId}`, {
        method: 'POST',
      })
      if (!r.ok) throw new Error(`Simulation failed (${r.status})`)
      setData(await r.json())
    } catch (e) {
      setError(asNetworkErrorMessage(e, 'Could not run attacker simulation.'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!scanId || data || loading) return
    runSimulation()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  return (
    <div className="mt-3 border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Attacker Simulation Mode
          </h3>
          <p className="mt-1 text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
            If I were an attacker, how could I exploit this PR?
          </p>
        </div>
        <button
          type="button"
          onClick={runSimulation}
          disabled={loading}
          className="border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-2 text-xs font-semibold uppercase tracking-[0.08em] text-white transition-colors hover:bg-ibm-blue-70 disabled:cursor-not-allowed disabled:border-ibm-gray-60 disabled:bg-ibm-gray-60"
        >
          {loading ? 'Simulating…' : 'Run simulation'}
        </button>
      </div>

      {error && (
        <div className="mt-3 border border-ibm-red-60 bg-[#2d1215] px-3 py-2 text-sm text-[#ffd7d9]">
          {error}
        </div>
      )}

      {data && (
        <div className="mt-4 space-y-4">
          <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
            <div className="bg-white p-3 dark:bg-ibm-gray-100">
              <p className="text-[10px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Threat level</p>
              <p className={`mt-1 text-lg font-light ${data.threat_level === 'CRITICAL' ? 'text-ibm-red-50' : data.threat_level === 'HIGH' ? 'text-ibm-orange-40' : 'text-carbon-text dark:text-ibm-gray-10'}`}>{data.threat_level}</p>
            </div>
            <div className="bg-white p-3 dark:bg-ibm-gray-100">
              <p className="text-[10px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Impact</p>
              <p className="mt-1 text-sm font-semibold text-ibm-red-50">{data.impact_level}</p>
            </div>
            <div className="bg-white p-3 dark:bg-ibm-gray-100">
              <p className="text-[10px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Confidence</p>
              <p className="mt-1 text-lg font-light text-carbon-text dark:text-ibm-gray-10">{Math.round((data.confidence || 0) * 100)}%</p>
            </div>
          </div>

          <div className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">Exploit path</p>
            {Array.isArray(data.exploit_path) && data.exploit_path.length > 0 ? (
              <p className="mt-2 font-mono text-xs text-carbon-text dark:text-ibm-gray-10">
                {data.exploit_path.join(' -> ')}
              </p>
            ) : (
              <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
                No explicit path in graph yet. Simulation used findings + threat context.
              </p>
            )}
          </div>

          <div className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">Step-by-step attack flow</p>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
              {(data.steps || []).map((step, idx) => (
                <li key={`${idx}-${step.slice(0, 12)}`}>{step}</li>
              ))}
            </ol>
          </div>

          <div className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">Why exploitable</p>
            <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">{data.why_exploitable}</p>
          </div>

          <div className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
            <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">Hardening actions</p>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
              {(data.recommendations || []).map((r, idx) => (
                <li key={`${idx}-${r.slice(0, 16)}`}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
