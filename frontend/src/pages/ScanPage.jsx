import { useState } from 'react'

const EXAMPLES = [
  {
    label: 'Dangerous agent tool',
    sub: 'LLM07 — shell exec',
    text: `from langchain.tools import tool\nimport subprocess\n\n@tool\ndef run_shell(command: str) -> str:\n    """Execute a shell command and return output."""\n    result = subprocess.run(command, shell=True, capture_output=True, text=True)\n    return result.stdout\n\n@tool\ndef read_file(path: str) -> str:\n    """Read contents of any file."""\n    with open(path) as f:\n        return f.read()`,
  },
  {
    label: 'LLM output to exec',
    sub: 'LLM02 — code execution',
    text: `from anthropic import Anthropic\n\nclient = Anthropic()\nresponse = client.messages.create(\n    model="claude-sonnet-4-20250514",\n    max_tokens=1024,\n    messages=[{"role": "user", "content": "Write a Python script to process data"}]\n)\n\ngenerated_code = response.content[0].text\nexec(generated_code)  # Arbitrary code execution from LLM output`,
  },
  {
    label: 'Unsanitized RAG',
    sub: 'LLM01 — prompt injection',
    text: `from langchain.vectorstores import Chroma\nfrom langchain.chat_models import ChatOpenAI\n\ndb = Chroma(persist_directory="./data")\nuser_query = input("Ask a question: ")\ndocs = db.similarity_search(user_query)\ncontext = "\\n".join([d.page_content for d in docs])\nprompt = f"Based on this context:\\n{context}\\n\\nAnswer: {user_query}"\nllm = ChatOpenAI()\nresult = llm.invoke(prompt)`,
  },
  {
    label: 'Secret leakage',
    sub: 'API key in prompt',
    text: `system = "You are an internal assistant. The OpenAI key is sk-proj-AbCdEfGh1234567890XyZ. Do not share it."\nuser_email = "alice@example.com"\nprompt = system + "\\nUser email: " + user_email`,
  },
]

const FULL_DEMO = `# PromptShield demo — dangerous AI agent with multiple vulnerability types
from langchain.tools import tool
from anthropic import Anthropic
import subprocess, os, sqlite3

API_KEY = "sk-proj-LiveSecretKey_DO_NOT_SHARE_1234567890"

@tool
def run_shell(command: str) -> str:
    """Execute a shell command and return output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

@tool
def run_query(query: str) -> str:
    """Run a SQL query against the application database."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())

client = Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Write cleanup script"}]
)
generated_code = response.content[0].text
exec(generated_code)  # LLM output executed directly`

export default function ScanPage({ onScan, loading, error }) {
  const [text, setText] = useState('')
  const [jbInput, setJbInput] = useState('')
  const [jbLoading, setJbLoading] = useState(false)
  const [jbResult, setJbResult] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (text.trim() && !loading) onScan(text)
  }

  const runJailbreakTest = async () => {
    if (!jbInput.trim() || jbLoading) return
    setJbLoading(true)
    setJbResult(null)
    try {
      const r = await fetch('/api/jailbreak/simulate/v2', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: jbInput }),
      })
      if (!r.ok) throw new Error('Simulation failed')
      const result = await r.json()
      setJbResult(result)
    } catch {
      setJbResult({
        overall: {
          vulnerable: false,
          confidence: 0,
          recommendation: 'Simulation unavailable right now. Try again in a moment.',
        },
        injection_results: [],
        defenses: {},
        interpolation_points: [],
      })
    } finally {
      setJbLoading(false)
    }
  }

  return (
    <div className="mx-auto w-full max-w-5xl px-6 py-10">
      <div className="mb-8">
        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ibm-blue-70 dark:text-ibm-blue-40">
          Prompt security · static + AI semantic analysis
        </p>
        <h1 className="mt-2 font-light text-4xl leading-tight text-carbon-text dark:text-ibm-gray-10">
          Scan prompts and code for vulnerabilities
        </h1>
        <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
          PromptShield runs a layered analysis pipeline against your prompt or
          source — pattern-based detectors plus a Claude-powered semantic auditor —
          and returns ranked findings mapped to CWE and OWASP LLM Top&nbsp;10.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="border border-carbon-border bg-white dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="flex items-center justify-between border-b border-carbon-border bg-carbon-layer px-4 py-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 bg-ibm-blue-60" />
            <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Input
            </span>
          </div>
          <span className="font-mono text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            {text.length.toLocaleString()} chars
          </span>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste a prompt, system message, or source code containing prompts…"
          rows={14}
          spellCheck={false}
          className="block w-full resize-y bg-white p-4 font-mono text-[13px] leading-relaxed text-carbon-text placeholder:text-carbon-text-tertiary focus:outline-none dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:placeholder:text-ibm-gray-50"
          disabled={loading}
        />
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <p className="text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Inputs are scanned locally; secrets are redacted before persistence.
          </p>
          <div className="flex gap-0">
            <button
              type="button"
              onClick={() => setText(FULL_DEMO)}
              disabled={loading}
              className="border border-carbon-border bg-white px-4 py-2 text-sm font-medium text-carbon-text transition-colors hover:bg-carbon-layer disabled:opacity-50 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
            >
              Load demo
            </button>
            <button
              type="submit"
              disabled={loading || !text.trim()}
              className="inline-flex items-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70 disabled:cursor-not-allowed disabled:border-ibm-gray-30 disabled:bg-ibm-gray-30"
            >
              {loading ? (
                <>
                  <span className="h-3 w-3 animate-spin border-2 border-white/30 border-t-white" />
                  Scanning
                </>
              ) : (
                <>
                  Run scan
                  <span className="text-[16px] leading-none">→</span>
                </>
              )}
            </button>
          </div>
        </div>
        {loading && <div className="carbon-progress" />}
      </form>

      {error && (
        <div
          role="alert"
          className="mt-4 border-l-4 border-ibm-red-60 border-y border-r border-carbon-border bg-[#fff1f1] px-4 py-3 text-sm text-ibm-red-70 dark:border-ibm-gray-80 dark:bg-ibm-red-70/20 dark:text-ibm-red-50"
        >
          {error}
        </div>
      )}

      <section className="mt-10">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Vulnerable examples
          </h2>
          <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Click to load
          </span>
        </div>
        <div className="grid grid-cols-1 gap-px bg-carbon-border md:grid-cols-2 lg:grid-cols-4 dark:bg-ibm-gray-80">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.label}
              type="button"
              onClick={() => setText(ex.text)}
              disabled={loading}
              className="group flex flex-col items-start bg-white px-4 py-4 text-left transition-colors hover:bg-ibm-blue-10 disabled:opacity-50 dark:bg-ibm-gray-90 dark:hover:bg-ibm-blue-90/30"
            >
              <span className="text-sm font-semibold text-carbon-text group-hover:text-ibm-blue-80 dark:text-ibm-gray-10 dark:group-hover:text-ibm-blue-30">
                {ex.label}
              </span>
              <span className="mt-1 text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                {ex.sub}
              </span>
              <span className="mt-3 font-mono text-[11px] text-ibm-blue-70 opacity-0 transition-opacity group-hover:opacity-100 dark:text-ibm-blue-30">
                Load →
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="mt-10 border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Jailbreak simulator
          </h2>
          <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Test if a flagged prompt is exploitable
          </span>
        </div>
        <textarea
          value={jbInput}
          onChange={(e) => setJbInput(e.target.value)}
          placeholder="Paste a risky prompt template or code snippet to simulate jailbreak payloads..."
          rows={5}
          spellCheck={false}
          className="block w-full resize-y border border-carbon-border bg-white p-3 font-mono text-[12px] leading-relaxed text-carbon-text placeholder:text-carbon-text-tertiary focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
        />
        <div className="mt-3 flex items-center gap-3">
          <button
            type="button"
            onClick={runJailbreakTest}
            disabled={jbLoading || !jbInput.trim()}
            className="inline-flex items-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70 disabled:cursor-not-allowed disabled:border-ibm-gray-30 disabled:bg-ibm-gray-30"
          >
            {jbLoading ? 'Testing…' : 'Run simulation'}
          </button>
          {jbResult && jbResult.overall && (
            <span className={`text-sm font-medium ${jbResult.overall.vulnerable ? 'text-ibm-red-60' : 'text-ibm-green-60'}`}>
              {jbResult.overall.vulnerable ? 'Likely exploitable' : 'No obvious exploit path'}
              {' · '}confidence {(Math.round((jbResult.overall.confidence || 0) * 100))}%
            </span>
          )}
        </div>
        {jbResult && jbResult.overall && (
          <div className="mt-3 space-y-2">
            <p className="text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
              {jbResult.overall.recommendation}
            </p>
            {/* Defenses summary */}
            {jbResult.defenses && (
              <div className="flex flex-wrap gap-3 text-xs mt-2">
                {Object.entries(jbResult.defenses).map(([k, v]) => (
                  <span key={k} className={`px-2 py-1 rounded border ${v ? 'bg-green-100 border-green-300 text-green-700' : 'bg-red-100 border-red-300 text-red-700'}`}>
                    {k.replace(/_/g, ' ')}: {v ? '✔' : '✗'}
                  </span>
                ))}
              </div>
            )}
            {/* Interpolation points */}
            {jbResult.interpolation_points && jbResult.interpolation_points.length > 0 && (
              <div className="mt-2 text-xs">
                <b>Interpolation points:</b> {jbResult.interpolation_points.map(p => p.variable).join(', ')}
              </div>
            )}
            {/* Injection results */}
            {Array.isArray(jbResult.injection_results) && jbResult.injection_results.length > 0 && (
              <div className="overflow-x-auto border border-carbon-border dark:border-ibm-gray-80 mt-2">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-carbon-border bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
                      <th className="px-3 py-2">Variable</th>
                      <th className="px-3 py-2">Payload</th>
                      <th className="px-3 py-2">Likely Effective</th>
                      <th className="px-3 py-2">Checks Failed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jbResult.injection_results.flatMap((point) =>
                      point.payloads.map((payload, idx) => (
                        <tr key={point.variable + idx} className="border-b border-carbon-border/70 dark:border-ibm-gray-80/70">
                          <td className="px-3 py-2 font-mono">{point.variable}</td>
                          <td className="px-3 py-2 text-carbon-text-secondary dark:text-ibm-gray-30">{payload.payload_preview}</td>
                          <td className={`px-3 py-2 ${payload.likely_effective ? 'text-ibm-red-60' : 'text-ibm-green-60'}`}>{payload.likely_effective ? 'Yes' : 'No'}</td>
                          <td className="px-3 py-2">
                            {payload.checks && Object.entries(payload.checks).filter(([k, v]) => v && v[0] === false).map(([k, v]) => (
                              <div key={k} className="text-red-600">{k.replace(/_/g, ' ')}: {v[1]}</div>
                            ))}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
