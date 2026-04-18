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

  return (
    <div
      className={`flex h-full min-h-screen flex-col ${
        isHome ? 'bg-[#07111d] text-white' : 'app-shell bg-carbon-bg text-carbon-text'
      }`}
    >
      {!isHome && (
        <header className="app-header flex h-14 items-stretch border-b border-carbon-border text-ibm-gray-100">
          <button
            onClick={() => setView('home')}
            className="flex items-center gap-3 border-r border-carbon-border px-5 transition-colors hover:bg-white/5"
          >
            <span
              aria-hidden
              className="font-display text-[24px] font-semibold tracking-[-0.06em] text-white"
            >
              PS
            </span>
            <span className="flex flex-col items-start leading-tight">
              <span className="terminal-mono text-[14px] font-semibold tracking-[-0.02em] text-white">
                PromptShield
              </span>
              <span className="terminal-label text-[9px] font-medium text-[#89a8d5]">
                AI Security Control Plane
              </span>
            </span>
          </button>
          <div className="terminal-mono hidden min-w-[160px] items-center border-r border-carbon-border px-4 text-[12px] text-[#8aa6d2] md:flex">
            Frontend command center
          </div>
          <nav className="flex items-center gap-2 px-3 text-[13px]">
            {NAV.map((item) => (
              <button
                key={item.id}
                onClick={() => setView(item.id)}
                className={`app-pill terminal-mono px-4 py-2 transition-colors ${
                  view === item.id
                    ? 'border-[#88b6ff] bg-[#14305a] text-white'
                    : 'text-[#aac3e8] hover:bg-white/8 hover:text-white'
                }`}
              >
                {item.label}
              </button>
            ))}
            <button
              onClick={() => report && setView('report')}
              disabled={!report}
              className={`app-pill terminal-mono px-4 py-2 transition-colors disabled:cursor-not-allowed disabled:text-carbon-text-tertiary ${
                view === 'report'
                  ? 'border-[#88b6ff] bg-[#14305a] text-white'
                  : 'text-[#aac3e8] hover:bg-white/8 hover:text-white'
              }`}
            >
              Report
              {report && (
                <span className="ml-2 inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-[#4b8dff] px-1.5 text-[11px] font-semibold text-white">
                  {report.total_count}
                </span>
              )}
            </button>
          </nav>
          <div className="ml-auto flex items-center gap-3 border-l border-carbon-border px-4 text-[11px] text-[#aac3e8]">
            <span className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-[#5ec8ff]" />
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
        className={`grid flex-1 grid-cols-1 ${showSidebar ? 'lg:grid-cols-[1fr,300px]' : ''}`}
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
          {view === 'login' && <LoginPage onLoggedIn={() => setView('pm')} />}
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
