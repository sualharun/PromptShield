import { useEffect, useState } from 'react'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

export default function PolicyPage() {
  const [exampleYaml, setExampleYaml] = useState('')
  const [yamlText, setYamlText] = useState('')
  const [result, setResult] = useState(null)
  const [validating, setValidating] = useState(false)

  useEffect(() => {
    fetchWithTimeout('/api/policy/example')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data?.yaml) {
          setExampleYaml(data.yaml)
          setYamlText(data.yaml)
        }
      })
      .catch(() => {})
  }, [])

  const validate = async () => {
    setValidating(true)
    setResult(null)
    try {
      const r = await fetchWithTimeout('/api/policy/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: yamlText }),
      })
      const body = await r.json()
      setResult(body)
    } catch (e) {
      setResult({ valid: false, error: e.message || 'Validation failed' })
    } finally {
      setValidating(false)
    }
  }

  const resetToExample = () => {
    setYamlText(exampleYaml)
    setResult(null)
  }

  return (
    <div className="mx-auto w-full max-w-6xl px-6 py-8">
      <div className="mb-6">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
          Policy-as-code · enforceable security gates
        </p>
        <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
          Your <span className="font-mono text-[0.75em]">.promptshield.yml</span> policy
        </h1>
        <p className="mt-1 max-w-2xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Drop a <span className="font-mono">.promptshield.yml</span> file at the root of
          any connected repo. PromptShield fetches it on every PR and uses it to drive
          the Check Run conclusion.
        </p>
      </div>

      <section className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              YAML editor
            </h2>
            <button
              onClick={resetToExample}
              className="text-[11px] text-ibm-blue-60 hover:underline dark:text-ibm-blue-40"
            >
              Reset to example
            </button>
          </div>
          <textarea
            value={yamlText}
            onChange={(e) => setYamlText(e.target.value)}
            spellCheck={false}
            rows={18}
            className="w-full resize-none border border-carbon-border bg-ibm-gray-100 p-3 font-mono text-[12px] leading-relaxed text-ibm-gray-10 focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80"
          />
          <button
            onClick={validate}
            disabled={validating}
            className="mt-3 border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white hover:bg-ibm-blue-70 disabled:opacity-60"
          >
            {validating ? 'Validating…' : 'Validate policy'}
          </button>
        </div>

        <div className="bg-white p-5 dark:bg-ibm-gray-90">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Validation result
          </h2>
          {!result && (
            <p className="text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Click <span className="font-medium">Validate policy</span> to parse your YAML
              and see the resolved configuration.
            </p>
          )}
          {result && !result.valid && (
            <div className="border border-ibm-red-60 bg-[#fff1f1] px-3 py-2 text-[12px] text-ibm-red-60 dark:bg-ibm-red-60/10">
              <div className="font-semibold">Invalid policy</div>
              <div className="mt-1 font-mono">{result.error}</div>
            </div>
          )}
          {result && result.valid && (
            <div className="space-y-3 text-[12px]">
              <div className="border border-ibm-green-60 bg-[#defbe6] px-3 py-2 text-ibm-green-60 dark:bg-ibm-green-60/10">
                Policy parsed successfully.
              </div>
              {result.warnings && result.warnings.length > 0 && (
                <div className="border border-[#f1c21b] bg-[#fffbea] px-3 py-2 text-[#b8470c] dark:bg-[#b8470c]/10">
                  <div className="font-semibold">Warnings</div>
                  <ul className="mt-1 list-disc pl-5">
                    {result.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div>
                <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                  Resolved policy
                </div>
                <pre className="mt-1 max-h-64 overflow-auto border border-carbon-border bg-ibm-gray-100 p-3 font-mono text-[11px] leading-relaxed text-ibm-gray-10 dark:border-ibm-gray-80">
                  {JSON.stringify(result.policy, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="mt-6 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          Supported fields
        </h2>
        <dl className="grid gap-4 text-[12px] md:grid-cols-2">
          <div>
            <dt className="font-semibold font-mono">min_score</dt>
            <dd className="mt-1 text-carbon-text-secondary dark:text-ibm-gray-30">
              Block the PR when <span className="font-mono">risk_score ≥ min_score</span>.
              Defaults to the global <span className="font-mono">RISK_GATE_THRESHOLD</span>.
            </dd>
          </div>
          <div>
            <dt className="font-semibold font-mono">block_if</dt>
            <dd className="mt-1 text-carbon-text-secondary dark:text-ibm-gray-30">
              Mapping of severity → count. Example:{' '}
              <span className="font-mono">{'{critical: 1, high: 3}'}</span>.
            </dd>
          </div>
          <div>
            <dt className="font-semibold font-mono">ignore</dt>
            <dd className="mt-1 text-carbon-text-secondary dark:text-ibm-gray-30">
              Drop findings by <span className="font-mono">types</span> (scanner
              type names) or <span className="font-mono">cwes</span> before scoring.
            </dd>
          </div>
          <div>
            <dt className="font-semibold font-mono">severity_overrides</dt>
            <dd className="mt-1 text-carbon-text-secondary dark:text-ibm-gray-30">
              Rewrite the severity of a given finding type.
              Example: <span className="font-mono">OVERLY_PERMISSIVE: low</span>.
            </dd>
          </div>
        </dl>
      </section>
    </div>
  )
}
