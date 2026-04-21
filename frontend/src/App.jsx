import { useCallback, useEffect, useState } from 'react'
import ScanPage from './pages/ScanPage.jsx'
import ReportPage from './pages/ReportPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import LandingPage from './pages/LandingPage.jsx'
import CompliancePage from './pages/CompliancePage.jsx'
import PMPage from './pages/PMPage.jsx'
import PolicyPage from './pages/PolicyPage.jsx'
import EnterprisePage from './pages/EnterprisePage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import AgentsPage from './pages/AgentsPage.jsx'
import AgentToolsPage from './pages/AgentToolsPage.jsx'
import ScanHistory from './components/ScanHistory.jsx'
import ThemeToggle, { useTheme } from './components/ThemeToggle.jsx'
import AuthBadge from './components/AuthBadge.jsx'
import { AuthProvider, useAuth } from './auth/AuthContext.jsx'
import { fetchWithTimeout, asNetworkErrorMessage } from './lib/fetchWithTimeout.js'
import {
  createAgentAccountApi,
  deleteAgentAccountApi,
  fetchAgentAccountsApi,
  loadAgentAccounts,
  saveAgentAccounts,
} from './lib/agentAccounts.js'

const API = ''

/** POST /api/scan can exceed 30s when Gemini + embeddings run; keep above worst-case latency. */
const SCAN_FETCH_TIMEOUT_MS = 120_000

const NAV = [
  { id: 'home', label: 'Home' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'pm', label: 'PM' },
  { id: 'policy', label: 'Policy' },
  { id: 'agents', label: 'Agents' },
  { id: 'agent-tools', label: 'Agent tools' },
  { id: 'enterprise', label: 'Enterprise' },
  { id: 'scan', label: 'Scan' },
]

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  )
}

function AppShell() {
  const { user, loading: authLoading } = useAuth()
  const [view, setView] = useState('home')
  const [pendingView, setPendingView] = useState(null)
  const [report, setReport] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [agentAccounts, setAgentAccounts] = useState([])
  useTheme()

  useEffect(() => {
    saveAgentAccounts(agentAccounts)
  }, [agentAccounts])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const accounts = await fetchAgentAccountsApi()
        if (cancelled) return
        setAgentAccounts(accounts)
        saveAgentAccounts(accounts)
      } catch {
        if (cancelled) return
        setAgentAccounts(loadAgentAccounts())
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

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

  useEffect(() => {
    if (!authLoading && !user && view === 'pm') {
      setPendingView(view)
      setView('login')
    }
  }, [authLoading, user, view])

  const runScan = useCallback(
    async (text) => {
      setLoading(true)
      setError(null)
      try {
        const r = await fetchWithTimeout(`${API}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        }, SCAN_FETCH_TIMEOUT_MS)
        if (!r.ok) {
          const detail = await r.json().catch(() => ({}))
          throw new Error(detail.detail || `Scan failed (${r.status})`)
        }
        const data = await r.json()
        setReport(data)
        setView('report')
        refreshHistory()
      } catch (e) {
        setError(asNetworkErrorMessage(e, 'Scan failed. Is the backend running on port 8000?'))
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
  const showSidebar = view !== 'home' && view !== 'login' && view !== 'dashboard'
  const goLogin = () => setView('login')

  const goDashboard = useCallback(() => {
    setView('dashboard')
  }, [])

  const goProtected = useCallback(
    (nextView) => {
      if (authLoading) return
      if (!user) {
        setPendingView(nextView)
        setView('login')
        return
      }
      setView(nextView)
    },
    [authLoading, user]
  )

  const addAgentAccount = useCallback(async (account) => {
    const created = await createAgentAccountApi(account)
    setAgentAccounts((current) => [created, ...current.filter((item) => item.id !== created.id)])
    return created
  }, [])

  const removeAgentAccount = useCallback(async (id) => {
    await deleteAgentAccountApi(id)
    setAgentAccounts((current) => current.filter((item) => item.id !== id))
  }, [])

  return (
    <div
      className={`flex h-full min-h-screen flex-col ${
        isHome
          ? 'bg-[#f4f4f4] text-carbon-text'
          : 'light-workspace bg-[#f3f1ea] text-carbon-text'
      }`}
    >
      {!isHome && (
        <header className="flex h-12 items-stretch border-b border-[#de715d]/28 bg-[#16213e] text-white">
          <button
            onClick={() => setView('home')}
            className="flex items-center gap-3 border-r border-[#de715d]/28 px-4 transition-colors hover:bg-white/8"
          >
            <span aria-hidden className="font-mono text-[15px] font-bold tracking-tight">IBM</span>
            <span className="flex flex-col items-start leading-tight">
              <span className="text-[14px] font-medium">PromptShield</span>
              <span
                className="text-[12px] font-semibold tracking-normal text-white"
                style={{ fontFamily: '"SF Pro Text", "Inter", "Segoe UI", "IBM Plex Sans", sans-serif' }}
              >
                Security Prompt Audit
              </span>
            </span>
          </button>
          <div className="hidden min-w-[140px] items-center border-r border-[#de715d]/28 px-4 text-[12px] text-white/66 md:flex">
            All projects
          </div>
          <nav className="flex items-stretch text-[13px]">
            {NAV.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  if (item.id === 'dashboard') {
                    goDashboard()
                    return
                  }
                  if (item.id === 'pm') {
                    goProtected('pm')
                    return
                  }
                  setView(item.id)
                }}
                className={`px-4 transition-colors ${
                  view === item.id
                    ? 'border-b-2 border-b-[#de715d] bg-white/8 text-white'
                    : 'text-white/68 hover:bg-white/8 hover:text-white'
                }`}
              >
                {item.label}
              </button>
            ))}
            <button
              onClick={() => report && setView('report')}
              disabled={!report}
              className={`px-4 transition-colors disabled:cursor-not-allowed disabled:text-carbon-text-tertiary ${
                view === 'report'
                  ? 'border-b-2 border-b-[#de715d] bg-white/8 text-white'
                  : 'text-white/68 hover:bg-white/8 hover:text-white'
              }`}
            >
              Report
              {report && (
                <span className="ml-2 inline-flex h-5 min-w-5 items-center justify-center bg-[#de715d] px-1.5 text-[11px] font-semibold text-white">
                  {report.total_count}
                </span>
              )}
            </button>
          </nav>
          <div className="ml-auto flex items-center gap-3 border-l border-[#de715d]/28 px-4 text-[11px] text-white/68">
            <span className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 bg-[#de715d]" />
              <span>API connected</span>
            </span>
            <span className="hidden font-mono uppercase tracking-wider md:inline">
              v0.3.0
            </span>
            <AuthBadge onSignIn={goLogin} />
            <ThemeToggle />
          </div>
        </header>
      )}

      <div
        className={`grid flex-1 grid-cols-1 ${
          showSidebar ? 'lg:grid-cols-[1fr,300px]' : ''
        }`}
      >
        <main className="overflow-y-auto bg-[#f3f1ea]">
          {error && (
            <div className="mx-auto mt-3 w-full max-w-6xl border border-[#de715d]/40 bg-[#fff1ec] px-4 py-2 text-sm text-[#8f3c2d]">
              {error}
            </div>
          )}
          {view === 'home' && (
            <LandingPage
              onEnterDashboard={goDashboard}
              onEnterScan={() => setView('scan')}
            />
          )}
          {view === 'scan' && (
            <ScanPage onScan={runScan} loading={loading} error={error} />
          )}
          {view === 'dashboard' && (
            <DashboardPage onSelectScan={loadScan} agentAccounts={agentAccounts} />
          )}
          {view === 'compliance' && <CompliancePage />}
          {view === 'pm' && <PMPage onSignIn={goLogin} />}
          {view === 'policy' && <PolicyPage />}
          {view === 'agents' && (
            <AgentsPage
              agentAccounts={agentAccounts}
              onAddAccount={addAgentAccount}
              onRemoveAccount={removeAgentAccount}
              scans={history}
            />
          )}
          {view === 'agent-tools' && <AgentToolsPage />}
          {view === 'enterprise' && <EnterprisePage />}
          {view === 'login' && (
            <LoginPage
              onLoggedIn={() => {
                setView(pendingView || 'pm')
                setPendingView(null)
              }}
            />
          )}
          {view === 'report' && (
            <ReportPage
              report={report}
              history={history}
              onNewScan={() => setView('scan')}
            />
          )}
        </main>
        {showSidebar && (
          <ScanHistory
            scans={history}
            activeId={report?.id}
            onSelect={loadScan}
          />
        )}
      </div>

      {!isHome && (
        <footer className="border-t border-[#de715d]/26 bg-[#16213e] px-6 py-2 text-[11px] text-white/68">
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <span>PromptShield · Prompt security for production AI systems</span>
            <span className="font-mono">Carbon Design System</span>
          </div>
        </footer>
      )}
    </div>
  )
}
