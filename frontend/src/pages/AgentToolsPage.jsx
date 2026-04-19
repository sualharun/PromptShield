import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  Bell,
  Check,
  ChevronDown,
  Database,
  RefreshCw,
  Search,
  Sparkles,
  TrendingDown,
  TrendingUp,
  X,
} from 'lucide-react'
import {
  asNetworkErrorMessage,
  fetchWithTimeout,
} from '../lib/fetchWithTimeout.js'

/** Agent / Mongo calls can exceed the default 30s (cold Atlas, embeddings). */
const AGENT_READ_TIMEOUT_MS = 90_000
const EXPLOIT_SEED_TIMEOUT_MS = 180_000

/**
 * AgentToolsPage — the "MongoDB Atlas for agent security" page.
 *
 * Surfaces (visibly, with feature labels) five Atlas capabilities:
 *   1. Document model + JSON Schema  → tool registry list cards
 *   2. Hybrid Search ($rankFusion)   → search bar with vector + lexical
 *   3. Vector Search                 → "Find similar exploits" modal
 *   4. Time-series collection        → 30-day attack-surface sparkline
 *   5. Change Stream / Atlas Trigger → critical alerts feed (acknowledgeable)
 *
 * All endpoints are graceful: each section degrades to its own empty/error
 * state without taking down the page.
 */
export default function AgentToolsPage() {
  // ── Tool registry (default + filters) ──────────────────────────────────
  const [tools, setTools] = useState([])
  const [toolsLoading, setToolsLoading] = useState(true)
  const [toolsError, setToolsError] = useState(null)
  const [filters, setFilters] = useState({
    framework: '',
    risk_level: '',
    capability: '',
  })

  // ── Hybrid search ──────────────────────────────────────────────────────
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null) // null = show full registry
  const [searchLoading, setSearchLoading] = useState(false)
  const [searchError, setSearchError] = useState(null)

  // ── Similar-exploits modal ─────────────────────────────────────────────
  const [exploitTool, setExploitTool] = useState(null)
  const [exploitMatches, setExploitMatches] = useState([])
  const [exploitLoading, setExploitLoading] = useState(false)
  const [exploitError, setExploitError] = useState(null)
  const [exploitBackend, setExploitBackend] = useState(null)

  // ── Alerts feed ────────────────────────────────────────────────────────
  const [alerts, setAlerts] = useState([])
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [triggerStatus, setTriggerStatus] = useState(null)

  // ── Time-series ────────────────────────────────────────────────────────
  const [timeline, setTimeline] = useState({ points: [], trend: null })
  const [timelineLoading, setTimelineLoading] = useState(false)

  // ── Capability + framework rollups ─────────────────────────────────────
  const [capRollup, setCapRollup] = useState([])
  const [fwRollup, setFwRollup] = useState([])

  const [seedRunning, setSeedRunning] = useState(false)
  const [seedMsg, setSeedMsg] = useState(null)

  // ── Loaders ────────────────────────────────────────────────────────────
  const loadTools = useCallback(async () => {
    setToolsLoading(true)
    setToolsError(null)
    try {
      const params = new URLSearchParams()
      if (filters.framework) params.set('framework', filters.framework)
      if (filters.risk_level) params.set('risk_level', filters.risk_level)
      if (filters.capability) params.set('capability', filters.capability)
      params.set('limit', '100')
      const r = await fetchWithTimeout(
        `/api/v2/agent-tools?${params}`,
        {},
        AGENT_READ_TIMEOUT_MS
      )
      if (!r.ok) throw new Error(`tool registry unavailable (${r.status})`)
      const data = await r.json()
      setTools(data.tools || [])
      if (data.degraded) {
        setToolsError(
          'MongoDB unavailable — the registry cannot be loaded. Check MONGODB_URI / Atlas access, or remove MONGODB_URI to use the built-in local mock.'
        )
      }
    } catch (e) {
      setToolsError(
        asNetworkErrorMessage(e, String(e.message || e))
      )
      setTools([])
    } finally {
      setToolsLoading(false)
    }
  }, [filters.framework, filters.risk_level, filters.capability])

  const loadAlerts = useCallback(async () => {
    setAlertsLoading(true)
    try {
      const r = await fetchWithTimeout(
        '/api/v2/agent-alerts?acknowledged=false&limit=20',
        {},
        AGENT_READ_TIMEOUT_MS
      )
      if (!r.ok) throw new Error(`alerts unavailable (${r.status})`)
      const data = await r.json()
      setAlerts(data.alerts || [])
      setTriggerStatus(data.trigger_status || null)
    } catch {
      setAlerts([])
      setTriggerStatus(null)
    } finally {
      setAlertsLoading(false)
    }
  }, [])

  const loadTimeline = useCallback(async () => {
    setTimelineLoading(true)
    try {
      const r = await fetchWithTimeout(
        '/api/v2/agent-surface-timeline?days=30',
        {},
        AGENT_READ_TIMEOUT_MS
      )
      if (!r.ok) throw new Error('timeline unavailable')
      const data = await r.json()
      setTimeline({
        points: data.points || [],
        trend: data.trend || null,
      })
    } catch {
      setTimeline({ points: [], trend: null })
    } finally {
      setTimelineLoading(false)
    }
  }, [])

  const loadRollups = useCallback(async () => {
    try {
      const [c, f] = await Promise.all([
        fetchWithTimeout(
          '/api/v2/agent-tools/aggregations/capabilities',
          {},
          AGENT_READ_TIMEOUT_MS
        )
          .then((r) => (r.ok ? r.json() : { capabilities: [] }))
          .catch(() => ({ capabilities: [] })),
        fetchWithTimeout(
          '/api/v2/agent-tools/aggregations/frameworks',
          {},
          AGENT_READ_TIMEOUT_MS
        )
          .then((r) => (r.ok ? r.json() : { frameworks: [] }))
          .catch(() => ({ frameworks: [] })),
      ])
      setCapRollup(c.capabilities || [])
      setFwRollup(f.frameworks || [])
    } catch {
      setCapRollup([])
      setFwRollup([])
    }
  }, [])

  useEffect(() => {
    loadTools()
  }, [loadTools])
  useEffect(() => {
    loadAlerts()
    loadTimeline()
    loadRollups()
  }, [loadAlerts, loadTimeline, loadRollups])

  // ── Hybrid search ──────────────────────────────────────────────────────
  const runSearch = async (e) => {
    e?.preventDefault?.()
    const q = query.trim()
    if (!q) {
      setResults(null)
      setSearchError(null)
      return
    }
    setSearchLoading(true)
    setSearchError(null)
    try {
      const r = await fetchWithTimeout(
        '/api/v2/agent-tools/search',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ q, k: 25, vector_weight: 1.0, text_weight: 1.0 }),
        },
        AGENT_READ_TIMEOUT_MS
      )
      if (!r.ok) throw new Error(`hybrid search failed (${r.status})`)
      const data = await r.json()
      setResults(data.results || [])
    } catch (e) {
      setSearchError(String(e.message || e))
      setResults([])
    } finally {
      setSearchLoading(false)
    }
  }

  const clearSearch = () => {
    setQuery('')
    setResults(null)
    setSearchError(null)
  }

  // ── Similar exploits ──────────────────────────────────────────────────
  const openSimilarExploits = async (tool) => {
    setExploitTool(tool)
    setExploitMatches([])
    setExploitError(null)
    setExploitLoading(true)
    setExploitBackend(null)
    try {
      const r = await fetchWithTimeout(
        '/api/v2/agent-tools/similar-exploits',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tool_name: tool.tool_name || '',
            capabilities: tool.capabilities || [],
            framework: tool.framework || null,
            evidence: (tool.evidence_samples || [])[0] || null,
            k: 5,
          }),
        },
        AGENT_READ_TIMEOUT_MS
      )
      if (!r.ok) throw new Error(`vector search failed (${r.status})`)
      const data = await r.json()
      setExploitMatches(data.matches || [])
      setExploitBackend(data.backend || null)
    } catch (e) {
      setExploitError(String(e.message || e))
    } finally {
      setExploitLoading(false)
    }
  }

  // ── Acknowledge alert ──────────────────────────────────────────────────
  const acknowledgeAlert = async (alertId) => {
    try {
      const r = await fetchWithTimeout(
        `/api/v2/agent-alerts/${alertId}/acknowledge?by=demo-user`,
        { method: 'POST' }
      )
      if (r.ok) {
        setAlerts((curr) => curr.filter((a) => a.id !== alertId))
      }
    } catch {
      /* swallow */
    }
  }

  // ── Seed exploit corpus ────────────────────────────────────────────────
  const runSeed = async () => {
    setSeedRunning(true)
    setSeedMsg(null)
    try {
      const r = await fetchWithTimeout(
        '/api/v2/agent-tools/exploit-corpus/seed',
        { method: 'POST' },
        EXPLOIT_SEED_TIMEOUT_MS
      )
      if (!r.ok) throw new Error(`seed failed (${r.status})`)
      const data = await r.json()
      setSeedMsg(
        `Seeded · upserted ${data.upserted ?? data.count ?? '?'} exploit pattern${
          (data.upserted ?? data.count ?? 0) === 1 ? '' : 's'
        }.`
      )
    } catch (e) {
      setSeedMsg(`Seed failed (${asNetworkErrorMessage(e, String(e.message || e))})`)
    } finally {
      setSeedRunning(false)
    }
  }

  // ── Display set: search results override registry list ────────────────
  const display = results !== null ? results : tools
  const showingSearch = results !== null

  // KPI numbers
  const kpis = useMemo(() => {
    const total = tools.length
    const critical = tools.filter((t) => t.risk_level === 'critical').length
    const high = tools.filter((t) => t.risk_level === 'high').length
    const frameworks = new Set(tools.map((t) => t.framework).filter(Boolean)).size
    return { total, critical, high, frameworks }
  }, [tools])

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      {/* Hero */}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ibm-blue-70 dark:text-ibm-blue-40">
            <span className="text-[#13aa52]">◆</span> MongoDB Atlas · agent
            attack surface
          </p>
          <h1 className="mt-2 font-light text-3xl text-carbon-text dark:text-ibm-gray-10">
            Agent tool registry
          </h1>
          <p className="mt-1 max-w-3xl text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Every AI-exposed tool we've seen across your repos, ranked by what
            it can do and what's missing. Search blends vector + lexical; each
            tool can be cross-referenced against a curated exploit corpus via
            Atlas Vector Search.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              loadTools()
              loadAlerts()
              loadTimeline()
              loadRollups()
            }}
            disabled={toolsLoading}
            className="inline-flex items-center gap-2 border border-carbon-border bg-white px-3 py-2 text-[12px] font-medium text-carbon-text transition-colors hover:bg-carbon-layer disabled:opacity-50 dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${toolsLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={runSeed}
            disabled={seedRunning}
            title="Embeds the curated agent-exploit corpus into MongoDB Atlas (one-time per index)"
            className="inline-flex items-center gap-2 border border-[#13aa52] bg-[#13aa52] px-3 py-2 text-[12px] font-medium text-white transition-colors hover:bg-[#0e8a42] disabled:opacity-60"
          >
            <Sparkles className="h-3.5 w-3.5" />
            {seedRunning ? 'Seeding…' : 'Seed exploit corpus'}
          </button>
        </div>
      </div>

      {seedMsg && (
        <div className="mb-4 border-l-4 border-[#13aa52] border-y border-r border-carbon-border bg-[#defbe6] px-4 py-2 text-[12px] text-[#0f5132] dark:border-r-ibm-gray-80 dark:border-y-ibm-gray-80">
          {seedMsg}
        </div>
      )}

      {/* KPI strip */}
      <section className="mb-6 grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <KpiTile label="Tools discovered" value={kpis.total} accent="#0f62fe" featureLabel="Document model" />
        <KpiTile label="Critical" value={kpis.critical} accent="#a2191f" featureLabel="JSON Schema validation" />
        <KpiTile label="High" value={kpis.high} accent="#b8470c" />
        <KpiTile label="Frameworks" value={kpis.frameworks} accent="#525252" />
      </section>

      {/* Layout: main grid + sidebar */}
      <div className="grid gap-6 lg:grid-cols-[1fr,340px]">
        <div className="space-y-6">
          {/* Hybrid search + filters */}
          <section className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                <span className="text-[#13aa52]">◆</span> Hybrid search ·
                $rankFusion (vector + lexical)
              </h2>
              <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                /api/v2/agent-tools/search
              </span>
            </div>
            <form onSubmit={runSearch} className="flex gap-2">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-carbon-text-tertiary dark:text-ibm-gray-40" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="e.g. tools that touch the filesystem with no allowlist"
                  className="w-full border border-carbon-border bg-carbon-bg py-2 pl-9 pr-9 text-sm text-carbon-text placeholder:text-carbon-text-tertiary focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
                />
                {query && (
                  <button
                    type="button"
                    onClick={clearSearch}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-carbon-text-tertiary hover:text-carbon-text dark:text-ibm-gray-40 dark:hover:text-ibm-gray-10"
                    aria-label="Clear search"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
              <button
                type="submit"
                disabled={searchLoading}
                className="border border-ibm-blue-60 bg-ibm-blue-60 px-4 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70 disabled:opacity-50"
              >
                {searchLoading ? 'Searching…' : 'Search'}
              </button>
            </form>
            {searchError && (
              <p className="mt-2 text-[11px] text-ibm-red-60">{searchError}</p>
            )}

            {/* Filters (only when not searching) */}
            {!showingSearch && (
              <div className="mt-3 flex flex-wrap gap-2">
                <FilterSelect
                  value={filters.framework}
                  onChange={(v) => setFilters((f) => ({ ...f, framework: v }))}
                  label="Framework"
                  options={fwRollup.map((r) => r.framework || r._id || r.name).filter(Boolean)}
                />
                <FilterSelect
                  value={filters.risk_level}
                  onChange={(v) => setFilters((f) => ({ ...f, risk_level: v }))}
                  label="Risk"
                  options={['critical', 'high', 'medium', 'low']}
                />
                <FilterSelect
                  value={filters.capability}
                  onChange={(v) => setFilters((f) => ({ ...f, capability: v }))}
                  label="Capability"
                  options={capRollup
                    .map((r) => r.capability || r._id)
                    .filter(Boolean)}
                />
                {(filters.framework || filters.risk_level || filters.capability) && (
                  <button
                    type="button"
                    onClick={() =>
                      setFilters({ framework: '', risk_level: '', capability: '' })
                    }
                    className="border border-carbon-border bg-carbon-layer px-3 text-[12px] text-carbon-text-secondary transition-colors hover:bg-carbon-border dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30"
                  >
                    Clear
                  </button>
                )}
              </div>
            )}
          </section>

          {/* Tool list */}
          <section>
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                {showingSearch
                  ? `Search results · "${query}"`
                  : 'Discovered AI-exposed tools'}
              </h2>
              <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                {display.length} tool{display.length === 1 ? '' : 's'}
              </span>
            </div>

            {toolsLoading && !showingSearch && <PanelMsg text="Loading tool registry…" />}
            {toolsError && !showingSearch && (
              <PanelMsg
                text={
                  toolsError.startsWith('MongoDB unavailable') ||
                  toolsError.startsWith('Request timed out') ||
                  toolsError.includes('Failed to fetch')
                    ? toolsError
                    : `Tool registry unavailable (${toolsError}). Run a scan with agent code first; tools are derived from scan findings.`
                }
              />
            )}
            {!toolsLoading && !toolsError && display.length === 0 && (
              <PanelMsg
                text={
                  showingSearch
                    ? 'No tools match this query.'
                    : 'No tools discovered yet. Scan an AI-agent file (try the demos on the Scan page) to populate the registry.'
                }
              />
            )}

            {display.length > 0 && (
              <div className="grid gap-3 md:grid-cols-2">
                {display.map((tool) => (
                  <ToolCard
                    key={`${tool.id || tool.tool_name}-${tool.repo_full_name || ''}`}
                    tool={tool}
                    onSimilarExploits={() => openSimilarExploits(tool)}
                  />
                ))}
              </div>
            )}
          </section>
        </div>

        {/* Sidebar */}
        <aside className="space-y-6">
          {/* Atlas feature card */}
          <section className="border border-[#13aa52]/40 bg-[#f6fdf6] p-4 dark:border-[#13aa52]/30 dark:bg-[#0a1f12]">
            <div className="mb-2 flex items-center gap-2">
              <Database className="h-4 w-4 text-[#13aa52]" />
              <h3 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-[#0e8a42]">
                Atlas features on this page
              </h3>
            </div>
            <ul className="space-y-1.5 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
              <FeatureLine k="Document model" v="agent_tools collection" />
              <FeatureLine k="JSON Schema" v="server-side validation" />
              <FeatureLine k="$rankFusion" v="vector + lexical hybrid" />
              <FeatureLine k="Vector Search" v="agent_exploit_corpus" />
              <FeatureLine k="Time-series" v="agent_surface_timeline" />
              <FeatureLine k="Atlas Trigger" v="alert_on_critical_agent_finding" />
              <FeatureLine k="Aggregation" v="$group capabilities + frameworks" />
            </ul>
          </section>

          {/* Surface timeline */}
          <SurfaceTimelineCard
            timeline={timeline}
            loading={timelineLoading}
          />

          {/* Alerts feed */}
          <AlertsCard
            alerts={alerts}
            loading={alertsLoading}
            triggerStatus={triggerStatus}
            onAcknowledge={acknowledgeAlert}
          />
        </aside>
      </div>

      {/* Similar exploits modal */}
      {exploitTool && (
        <ExploitsModal
          tool={exploitTool}
          matches={exploitMatches}
          loading={exploitLoading}
          error={exploitError}
          backend={exploitBackend}
          onClose={() => setExploitTool(null)}
        />
      )}
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────

function KpiTile({ label, value, accent, featureLabel }) {
  return (
    <div className="bg-white px-5 py-4 dark:bg-ibm-gray-90">
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {label}
      </div>
      <div
        className="mt-2 font-light text-3xl tabular-nums"
        style={{ color: accent }}
      >
        {value}
      </div>
      {featureLabel && (
        <div className="mt-1 text-[10px] text-[#13aa52]">◆ {featureLabel}</div>
      )}
    </div>
  )
}

function FilterSelect({ value, onChange, label, options }) {
  return (
    <label className="inline-flex items-center gap-2 border border-carbon-border bg-carbon-bg pl-3 text-[12px] dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
      <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none border-l border-carbon-border bg-transparent py-1.5 pl-2 pr-6 text-carbon-text focus:outline-none dark:border-ibm-gray-80 dark:text-ibm-gray-10"
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  )
}

const RISK_TONE = {
  critical: { bar: '#a2191f', bg: '#fff1f1', text: '#a2191f' },
  high: { bar: '#b8470c', bg: '#fff8f1', text: '#b8470c' },
  medium: { bar: '#8a6800', bg: '#fff8e1', text: '#8a6800' },
  low: { bar: '#525252', bg: '#f4f4f4', text: '#525252' },
}

function fusionValue(raw) {
  // Atlas $rankFusion returns either a number (mongomock fallback) or a
  // nested object { value, description, details } when the real index is hit.
  if (raw == null) return null
  if (typeof raw === 'number') return raw
  if (typeof raw === 'object' && typeof raw.value === 'number') return raw.value
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}

function ToolCard({ tool, onSimilarExploits }) {
  const [open, setOpen] = useState(false)
  const tone = RISK_TONE[tool.risk_level] || RISK_TONE.low
  const fusion = fusionValue(tool.fusion_score)
  return (
    <div
      className="border-l-4 border-y border-r border-carbon-border bg-white dark:border-y-ibm-gray-80 dark:border-r-ibm-gray-80 dark:bg-ibm-gray-90"
      style={{ borderLeftColor: tone.bar }}
    >
      <div className="px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate font-mono text-[14px] font-semibold text-carbon-text dark:text-ibm-gray-10">
                {tool.tool_name || '(unnamed)'}
              </h3>
              <span
                className="font-mono text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: tone.text }}
              >
                {tool.risk_level || 'low'}
              </span>
              {fusion != null && (
                <span
                  className="ml-auto font-mono text-[10px] text-[#13aa52]"
                  title="Reciprocal-Rank-Fusion score (vector + lexical)"
                >
                  fusion {Number(fusion).toFixed(3)}
                </span>
              )}
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
              {tool.framework && (
                <span>
                  framework <span className="font-mono">{tool.framework}</span>
                </span>
              )}
              {tool.repo_full_name && (
                <span>
                  repo <span className="font-mono">{tool.repo_full_name}</span>
                </span>
              )}
              <span>
                seen <span className="font-mono">{tool.occurrences}×</span>
              </span>
            </div>
          </div>
        </div>

        {/* Capabilities */}
        {tool.capabilities && tool.capabilities.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {tool.capabilities.map((c) => (
              <span
                key={c}
                className="border border-carbon-border bg-carbon-layer px-1.5 py-0.5 font-mono text-[10px] text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30"
              >
                {c}
              </span>
            ))}
          </div>
        )}

        {/* Missing safeguards (the killer bit) */}
        {tool.missing_safeguards && tool.missing_safeguards.length > 0 && (
          <div className="mt-2 border-l-4 px-2.5 py-1.5 text-[11.5px]"
            style={{ borderColor: tone.bar, background: tone.bg, color: '#1c1c1c' }}>
            <span className="font-semibold">Missing:</span>{' '}
            {tool.missing_safeguards.join(', ')}
          </div>
        )}

        {/* Toggle */}
        <div className="mt-3 flex items-center justify-between gap-2">
          <button
            onClick={onSimilarExploits}
            className="inline-flex items-center gap-1.5 border border-[#13aa52] px-2.5 py-1 text-[11px] font-medium text-[#0e8a42] transition-colors hover:bg-[#13aa52] hover:text-white"
            title="Atlas Vector Search over agent_exploit_corpus"
          >
            <Sparkles className="h-3 w-3" />
            Find similar exploits
          </button>
          <button
            onClick={() => setOpen(!open)}
            className="inline-flex items-center gap-1 text-[11px] text-carbon-text-tertiary hover:text-carbon-text dark:text-ibm-gray-40 dark:hover:text-ibm-gray-10"
          >
            {open ? 'Hide' : 'Evidence'}
            <ChevronDown
              className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`}
            />
          </button>
        </div>

        {open && tool.evidence_samples && tool.evidence_samples.length > 0 && (
          <div className="mt-2 space-y-1">
            {tool.evidence_samples.slice(0, 3).map((ev, i) => (
              <pre
                key={i}
                className="overflow-x-auto border border-carbon-border bg-ibm-gray-100 p-2 font-mono text-[11px] leading-relaxed text-ibm-gray-10 dark:border-ibm-gray-80"
              >
                {ev}
              </pre>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function PanelMsg({ text }) {
  return (
    <div className="border border-carbon-border bg-carbon-layer px-4 py-6 text-center text-[13px] text-carbon-text-tertiary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-40">
      {text}
    </div>
  )
}

function FeatureLine({ k, v }) {
  return (
    <li className="flex items-baseline justify-between gap-2">
      <span className="font-mono text-[11px] text-[#0e8a42]">◆ {k}</span>
      <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {v}
      </span>
    </li>
  )
}

function SurfaceTimelineCard({ timeline, loading }) {
  const points = timeline.points || []
  const trend = timeline.trend
  return (
    <section className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          <span className="text-[#13aa52]">◆</span> Attack-surface timeline
        </h3>
        <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          time-series · 30d
        </span>
      </div>
      {loading && <PanelMsg text="Loading…" />}
      {!loading && points.length === 0 && (
        <PanelMsg text="No snapshots yet. Each scan adds a point." />
      )}
      {!loading && points.length > 0 && (
        <>
          <Sparkline points={points} />
          {trend && (
            <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
              <TrendStat
                label="Risk Δ"
                value={trend.risk_delta}
                inverted
              />
              <TrendStat label="Tools Δ" value={trend.surface_delta} inverted />
            </div>
          )}
        </>
      )}
    </section>
  )
}

function Sparkline({ points }) {
  // Simple inline SVG sparkline of agent_risk_score (with rolling avg overlay).
  const w = 280
  const h = 60
  const pad = 4
  if (!points.length) return null
  const xs = points.map((_, i) => i)
  const maxX = Math.max(1, xs.length - 1)
  const ys = points.map((p) => p.agent_risk_score || 0)
  const ysAvg = points.map((p) => p.rolling_7d_risk || 0)
  const maxY = Math.max(1, ...ys, ...ysAvg)
  const x = (i) => pad + (i / maxX) * (w - pad * 2)
  const y = (v) => h - pad - (v / maxY) * (h - pad * 2)
  const path = (vs) =>
    vs
      .map((v, i) => `${i === 0 ? 'M' : 'L'} ${x(i).toFixed(1)} ${y(v).toFixed(1)}`)
      .join(' ')

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      width="100%"
      height="60"
      preserveAspectRatio="none"
      className="block"
    >
      <path
        d={path(ys)}
        fill="none"
        stroke="#0f62fe"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d={path(ysAvg)}
        fill="none"
        stroke="#13aa52"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeDasharray="3 3"
      />
      {ys.map((v, i) => (
        <circle key={i} cx={x(i)} cy={y(v)} r={1.5} fill="#0f62fe" />
      ))}
    </svg>
  )
}

function TrendStat({ label, value, inverted }) {
  // `inverted` = up arrow is BAD (risk going up is bad)
  const v = Number(value || 0)
  const isUp = v > 0
  const isFlat = v === 0
  const bad = inverted ? isUp : !isUp
  const tone = isFlat
    ? '#525252'
    : bad
    ? '#a2191f'
    : '#198038'
  return (
    <div className="flex items-center gap-1.5">
      {isFlat ? (
        <span className="h-3 w-3 text-carbon-text-tertiary">·</span>
      ) : isUp ? (
        <TrendingUp className="h-3 w-3" style={{ color: tone }} />
      ) : (
        <TrendingDown className="h-3 w-3" style={{ color: tone }} />
      )}
      <span className="text-carbon-text-tertiary dark:text-ibm-gray-40">{label}</span>
      <span className="ml-auto font-mono tabular-nums" style={{ color: tone }}>
        {v > 0 ? `+${v}` : v}
      </span>
    </div>
  )
}

function AlertsCard({ alerts, loading, triggerStatus, onAcknowledge }) {
  const writtenByTrigger = triggerStatus?.atlas_trigger_active === true
  return (
    <section className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
          <Bell className="mr-1 inline h-3 w-3 text-ibm-blue-70" />
          Critical agent alerts
        </h3>
        <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          ◆ {writtenByTrigger ? 'atlas trigger' : 'change-stream / fallback'}
        </span>
      </div>
      {loading && <PanelMsg text="Loading…" />}
      {!loading && alerts.length === 0 && (
        <PanelMsg text="No unacknowledged critical alerts." />
      )}
      {!loading && alerts.length > 0 && (
        <ol className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
          {alerts.map((a) => (
            <li
              key={a.id}
              className="border-l-4 border-l-[#a2191f] border-y border-r border-carbon-border bg-[#fff1f1] px-3 py-2 dark:border-y-ibm-gray-80 dark:border-r-ibm-gray-80 dark:bg-ibm-red-60/10"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <AlertTriangle className="h-3 w-3 text-[#a2191f]" />
                    <span className="text-[12px] font-semibold text-[#a2191f]">
                      {a.title || a.finding_type}
                    </span>
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
                    {a.description || a.evidence || '—'}
                  </p>
                  <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                    {a.repo_full_name && <span>{a.repo_full_name}</span>}
                    {a.line_number != null && <span>L{a.line_number}</span>}
                    {a.cwe && <span className="font-mono">{a.cwe}</span>}
                    {a.occurrences > 1 && <span>×{a.occurrences}</span>}
                    {a.written_by === 'atlas_trigger' && (
                      <span className="font-mono text-[#0e8a42]">◆ trigger</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => onAcknowledge(a.id)}
                  title="Acknowledge"
                  className="border border-carbon-border bg-white p-1 text-carbon-text-secondary transition-colors hover:bg-carbon-layer hover:text-carbon-text dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
                >
                  <Check className="h-3 w-3" />
                </button>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}

function ExploitsModal({ tool, matches, loading, error, backend, onClose }) {
  const closeRef = useRef(null)

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-2xl border border-carbon-border bg-white shadow-2xl dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <div className="flex items-start justify-between gap-3 border-b border-carbon-border bg-carbon-layer px-5 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-[#0e8a42]">
              <span className="text-[#13aa52]">◆</span> Atlas Vector Search ·
              agent_exploit_corpus
            </p>
            <h3 className="mt-1 font-mono text-[15px] font-semibold text-carbon-text dark:text-ibm-gray-10">
              Similar known exploits to{' '}
              <span className="text-ibm-blue-70 dark:text-ibm-blue-30">
                {tool.tool_name}
              </span>
            </h3>
            {backend && (
              <p className="mt-0.5 font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                backend: {backend}
              </p>
            )}
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            className="border border-carbon-border bg-white p-1.5 text-carbon-text-secondary hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-80"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">
          {loading && (
            <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
              Querying Atlas Vector Search…
            </p>
          )}
          {error && (
            <p className="text-sm text-ibm-red-60">
              Lookup failed: {error}. Make sure the exploit corpus has been
              seeded (use the green "Seed exploit corpus" button on the page).
            </p>
          )}
          {!loading && !error && matches.length === 0 && (
            <p className="text-sm text-carbon-text-tertiary dark:text-ibm-gray-40">
              No similar exploits in the corpus. Try seeding it first.
            </p>
          )}
          {matches.length > 0 && (
            <ol className="space-y-3">
              {matches.map((m, i) => (
                <li
                  key={`${m.id || m.title || i}`}
                  className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
                >
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30">
                      #{i + 1}
                    </span>
                    {m.category && (
                      <span className="border border-carbon-border bg-white px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-30">
                        {m.category}
                      </span>
                    )}
                    {m.framework && (
                      <span className="font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                        {m.framework}
                      </span>
                    )}
                    <span
                      className="ml-auto font-mono text-[11px] font-semibold"
                      style={{ color: scoreColor(m.score) }}
                      title="Cosine similarity"
                    >
                      {Math.round((m.score || 0) * 100)}%
                    </span>
                  </div>
                  <h4 className="font-semibold text-[13px] text-carbon-text dark:text-ibm-gray-10">
                    {m.title || '(untitled)'}
                  </h4>
                  {m.exploit_summary && (
                    <p className="mt-1 text-[12px] leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
                      {m.exploit_summary}
                    </p>
                  )}
                  {m.remediation && (
                    <p className="mt-2 border-l-2 border-ibm-blue-60 bg-white px-2 py-1 text-[11.5px] text-carbon-text dark:bg-ibm-gray-90 dark:text-ibm-gray-10">
                      <span className="font-semibold">Fix:</span> {m.remediation}
                    </p>
                  )}
                  {m.cve_or_ref && (
                    <p className="mt-1 font-mono text-[10px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                      ref: {m.cve_or_ref}
                    </p>
                  )}
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  )
}

function scoreColor(s) {
  const v = Math.round((s || 0) * 100)
  if (v >= 90) return '#a2191f'
  if (v >= 75) return '#b8470c'
  if (v >= 60) return '#8a6800'
  return '#198038'
}
