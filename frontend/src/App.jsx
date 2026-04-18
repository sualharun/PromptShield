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
import ScanHistory from './components/ScanHistory.jsx'
import ThemeToggle, { useTheme } from './components/ThemeToggle.jsx'
import AuthBadge from './components/AuthBadge.jsx'
import { AuthProvider } from './auth/AuthContext.jsx'
import { fetchWithTimeout, asNetworkErrorMessage } from './lib/fetchWithTimeout.js'

const API = ''

const NAV = [
  { id: 'home', label: 'Home' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'pm', label: 'PM' },
  { id: 'policy', label: 'Policy' },
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
  const [view, setView] = useState('home')
  const [report, setReport] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  useTheme()

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
        const r = await fetchWithTimeout(`${API}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        }, 30000)
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
  const showSidebar = view !== 'home' && view !== 'login'
  const goLogin = () => setView('login')

  return (
    <div
      className={`flex h-full min-h-screen flex-col ${
        isHome
          ? 'bg-[#2f2d2b] text-white'
          : 'hackathon-ibm bg-carbon-bg text-carbon-text'
      }`}
    >
      {!isHome && (
        <header className="flex h-12 items-stretch border-b border-carbon-border bg-[#161616] text-ibm-gray-100">
          <button
            onClick={() => setView('home')}
            className="flex items-center gap-3 border-r border-carbon-border px-4 transition-colors hover:bg-carbon-layer"
          >
            <span aria-hidden className="font-mono text-[15px] font-bold tracking-tight">IBM</span>
            <span className="flex flex-col items-start leading-tight">
              <span className="text-[14px] font-medium">PromptShield</span>
              <span className="text-[10px] uppercase tracking-[0.12em] text-carbon-text-secondary">
                Security · Prompt Audit
              </span>
            </span>
          </button>
          <div className="hidden min-w-[140px] items-center border-r border-carbon-border px-4 text-[12px] text-carbon-text-secondary md:flex">
            All projects
          </div>
          <nav className="flex items-stretch text-[13px]">
            {NAV.map((item) => (
              <button
                key={item.id}
                onClick={() => setView(item.id)}
                className={`px-4 transition-colors ${
                  view === item.id
                    ? 'border-b-2 border-b-ibm-blue-60 bg-carbon-layer text-ibm-gray-10'
                    : 'text-carbon-text-secondary hover:bg-carbon-layer hover:text-ibm-gray-10'
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
                  ? 'border-b-2 border-b-ibm-blue-60 bg-carbon-layer text-ibm-gray-10'
                  : 'text-carbon-text-secondary hover:bg-carbon-layer hover:text-ibm-gray-10'
              }`}
            >
              Report
              {report && (
                <span className="ml-2 inline-flex h-5 min-w-5 items-center justify-center bg-ibm-blue-60 px-1.5 text-[11px] font-semibold text-white">
                  {report.total_count}
                </span>
              )}
            </button>
          </nav>
          <div className="ml-auto flex items-center gap-3 border-l border-carbon-border px-4 text-[11px] text-carbon-text-secondary">
            <span className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 bg-ibm-green-50" />
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
        <main className={`overflow-y-auto ${isHome ? 'bg-[#2f2d2b]' : 'bg-carbon-bg'}`}>
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
          {view === 'scan' && (
            <ScanPage onScan={runScan} loading={loading} error={error} />
          )}
          {view === 'dashboard' && <DashboardPage onSelectScan={loadScan} />}
          {view === 'compliance' && <CompliancePage />}
          {view === 'pm' && <PMPage onSignIn={goLogin} />}
          {view === 'policy' && <PolicyPage />}
          {view === 'enterprise' && <EnterprisePage />}
          {view === 'login' && (
            <LoginPage onLoggedIn={() => setView('pm')} />
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
        <footer className="border-t border-carbon-border bg-carbon-bg px-6 py-2 text-[11px] text-carbon-text-tertiary dark:border-ibm-gray-80 dark:text-ibm-gray-40">
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <span>PromptShield · Prompt security for production AI systems</span>
            <span className="font-mono">Carbon Design System</span>
          </div>
        </footer>
      )}
    </div>
  )
}
