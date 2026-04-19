import { useCallback, useEffect, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import ScanPage from './pages/ScanPage.jsx'
import ReportPage from './pages/ReportPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import LandingPage from './pages/LandingPage.jsx'
import CompliancePage from './pages/CompliancePage.jsx'
import PMPage from './pages/PMPage.jsx'
import PolicyPage from './pages/PolicyPage.jsx'
import EnterprisePage from './pages/EnterprisePage.jsx'
import AgentHandoffPage from './pages/AgentHandoffPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import ScanHistory from './components/ScanHistory.jsx'
import ThemeToggle, { useTheme } from './components/ThemeToggle.jsx'
import { AuthProvider, useAuth } from './auth/AuthContext.jsx'
import { fetchWithTimeout, asNetworkErrorMessage } from './lib/fetchWithTimeout.js'

const API = ''

const WORKSPACE_NAV = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'pm', label: 'PM' },
  { id: 'policy', label: 'Policy' },
  { id: 'enterprise', label: 'Enterprise' },
  { id: 'agent', label: 'Agent Handoff' },
  { id: 'scan', label: 'Scan' },
]

const LANDING_NAV = [
  { label: 'Platform', section: 'workflows' },
  { label: 'Outcomes', section: 'proof' },
  { label: 'Security', section: 'security' },
]

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  )
}

function AppShell() {
  const [view, setView] = useState('home')
  const [report, setReport] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [pendingHomeSection, setPendingHomeSection] = useState(null)
  useTheme()
  const { user, logout, loading: authLoading } = useAuth()

  const refreshHistory = useCallback(async () => {
    try {
      const r = await fetchWithTimeout(`${API}/api/scans`)
      if (r.ok) setHistory(await r.json())
    } catch {
      /* ignore */
    }
  }, [])

  useEffect(() => {
    refreshHistory()
  }, [refreshHistory])

  const runScan = useCallback(
    async (text) => {
      setLoading(true)
      setError(null)
      try {
        const r = await fetchWithTimeout(
          `${API}/api/scan`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text }),
          },
          30000
        )
        if (!r.ok) {
          const detail = await r.json().catch(() => ({}))
          throw new Error(detail.detail || `Scan failed (${r.status})`)
        }
        const data = await r.json()

// ML risk scoring
try {
  const mlR = await fetchWithTimeout(`${API}/api/risk-scoring`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repos: [{ repo: 'scanned-input', prompts: [text] }]
    }),
  }, 10000)
  if (mlR.ok) {
    const mlData = await mlR.json()
    const top = mlData.ranked_repos?.[0]
    if (top) {
      data.ml_risk_score = top.avg_risk_score
      data.ml_priority = top.priority
      data.ml_flagged = top.flagged_prompts
    }
  }
} catch {
  // non-blocking, don't fail the scan
}

setReport(data)
setView('report')
refreshHistory()
      } catch (e) {
        setError(
          asNetworkErrorMessage(e, 'Scan failed. Is the backend running on port 8000?')
        )
      } finally {
        setLoading(false)
      }
    },
    [refreshHistory]
  )

  const loadScan = useCallback(async (id) => {
    setError(null)
    try {
      const r = await fetchWithTimeout(`${API}/api/scans/${id}`)
      if (!r.ok) throw new Error('Could not load scan')
      const data = await r.json()
      setReport(data)
      setView('report')
    } catch (e) {
      setError(asNetworkErrorMessage(e, 'Could not load scan'))
    }
  }, [])

  const isHome = view === 'home'
  const showSidebar = view !== 'home' && view !== 'login'
  const goLogin = () => setView('login')
  const goHomeSection = useCallback((section) => {
    setPendingHomeSection(section)
    setView('home')
  }, [])

  useEffect(() => {
    if (view !== 'home' || !pendingHomeSection) return

    const timer = window.setTimeout(() => {
      const node = document.getElementById(pendingHomeSection)
      node?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      setPendingHomeSection(null)
    }, 60)

    return () => window.clearTimeout(timer)
  }, [view, pendingHomeSection])

  return (
    <div
      className={`flex h-full min-h-screen flex-col ${
        isHome ? 'bg-[#07111d] text-white' : 'app-shell bg-carbon-bg text-carbon-text'
      }`}
    >
      <header className="shared-topbar sticky top-0 z-40 px-4 py-3 sm:px-6 lg:px-8">
        <div className="shared-topbar-shell mx-auto flex max-w-[1680px] items-center gap-3 px-4 py-2.5">
          <button
            onClick={() => setView('home')}
            className="shared-topbar-brand flex items-center gap-3 text-left"
          >
            <span className="font-display text-[20px] font-semibold tracking-[-0.06em] text-white">
              PS
            </span>
            <span className="hidden terminal-mono text-[13px] font-semibold tracking-[-0.02em] text-white sm:inline">
              PromptShield
            </span>
          </button>

          <nav className="hidden items-center gap-1 lg:flex">
            {LANDING_NAV.map((item) => (
              <button
                key={item.section}
                onClick={() => goHomeSection(item.section)}
                className="shared-topbar-link"
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <details className="shared-topbar-dropdown group relative">
              <summary className="shared-topbar-link shared-topbar-summary list-none">
                <span>Workspace</span>
                <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" />
              </summary>
              <div className="shared-topbar-menu">
                {WORKSPACE_NAV.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setView(item.id)}
                    className={`shared-topbar-menu-item ${view === item.id ? 'is-active' : ''}`}
                  >
                    <span>{item.label}</span>
                    {item.id === 'report' && report ? (
                      <span className="shared-topbar-count">{report.total_count}</span>
                    ) : null}
                  </button>
                ))}
                <button
                  onClick={() => report && setView('report')}
                  disabled={!report}
                  className={`shared-topbar-menu-item ${view === 'report' ? 'is-active' : ''}`}
                >
                  <span>Report</span>
                  {report ? <span className="shared-topbar-count">{report.total_count}</span> : null}
                </button>
              </div>
            </details>

            {!authLoading && !user ? (
              <button onClick={goLogin} className="shared-topbar-ghost">
                Log in
              </button>
            ) : null}

            {!authLoading && user ? (
              <div className="hidden items-center gap-2 rounded-full border border-white/10 bg-[#08111d] px-3 py-2 text-[11px] text-[#c5d9f7] md:flex">
                <span className="font-medium text-white">{user.name}</span>
                <span className="rounded-full border border-white/10 px-2 py-0.5 uppercase tracking-[0.12em] text-[#8db4ff]">
                  {user.role}
                </span>
                <button onClick={logout} className="text-[#8eaad2] transition-colors hover:text-white">
                  Sign out
                </button>
              </div>
            ) : null}

            <button
              onClick={() => setView(isHome ? 'dashboard' : 'home')}
              className="shared-topbar-cta"
            >
              {isHome ? 'Access dashboard' : 'Back to home'}
            </button>

            <ThemeToggle />
          </div>
        </div>
      </header>

      <div
        className={`grid flex-1 grid-cols-1 ${showSidebar ? 'lg:grid-cols-[minmax(0,1fr),272px]' : ''}`}
      >
        <main className={`overflow-y-auto ${isHome ? 'bg-[#07111d]' : 'bg-carbon-bg'}`}>
          {error && (
            <div className="mx-auto mt-3 w-full max-w-6xl border border-ibm-red-60 bg-[#2d1215] px-4 py-2 text-sm text-[#ffd7d9]">
              {error}
            </div>
          )}
          {view === 'home' && (
            <LandingPage
              onEnterDashboard={() => setView('dashboard')}
              onEnterScan={() => setView('scan')}
            />
          )}
          {view === 'scan' && <ScanPage onScan={runScan} loading={loading} error={error} />}
          {view === 'dashboard' && <DashboardPage onSelectScan={loadScan} />}
          {view === 'compliance' && <CompliancePage />}
          {view === 'pm' && <PMPage onSignIn={goLogin} />}
          {view === 'policy' && <PolicyPage />}
          {view === 'enterprise' && <EnterprisePage />}

          {view === 'agent' && <AgentHandoffPage />}
          {view === 'login' && (
            <LoginPage onLoggedIn={() => setView('pm')} />
          )}
          {view === 'report' && (
            <ReportPage report={report} history={history} onNewScan={() => setView('scan')} />
          )}
        </main>
        {showSidebar && (
          <ScanHistory scans={history} activeId={report?.id} onSelect={loadScan} />
        )}
      </div>

      {!isHome && (
        <footer className="app-footer border-t border-carbon-border px-6 py-3 text-[11px] text-carbon-text-tertiary dark:border-ibm-gray-80 dark:text-ibm-gray-40">
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <span>PromptShield · Prompt security for production AI systems</span>
            <span className="font-mono">Terminal dashboard theme</span>
          </div>
        </footer>
      )}
    </div>
  )
}
