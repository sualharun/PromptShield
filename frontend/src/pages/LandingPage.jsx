import { useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import {
  ArrowRight,
  Bot,
  ChevronDown,
  FileCode2,
  GitPullRequest,
  ShieldAlert,
  TerminalSquare,
  Wrench,
} from 'lucide-react'

const NAV_DROPDOWNS = [
  {
    key: 'product',
    label: 'Product',
    previewTitle: 'Review prompts, repo instructions, and generated diffs before merge.',
    previewBody: 'PromptShield runs static rules, AST dataflow, and a Gemini semantic audit across prompts, tool surfaces, and generated diffs — then attaches evidence to the PR gate.',
    columns: [
      {
        heading: 'Platform',
        items: [
          {
            title: 'Agent review layer',
            description: 'Capture prompts, changed files, repo rules, and requested tool scopes before execution or merge.',
            action: 'workflow',
          },
          {
            title: 'Live demo',
            description: 'Replay a vulnerable coding-agent run locally without the backend.',
            action: 'demo',
          },
        ],
      },
      {
        heading: 'Operations',
        items: [
          {
            title: 'Dashboard',
            description: 'Open the GitHub PR workspace with risk, severity, and repository-level visibility.',
            action: 'dashboard',
          },
          {
            title: 'Metrics',
            description: 'Use the built-in benchmark, risk trend, and gate-failure metrics already exposed in the app.',
            action: 'metrics',
          },
        ],
      },
    ],
  },
  {
    key: 'solutions',
    label: 'Solutions',
    previewTitle: 'Security for Codex, Claude, Cursor, and GitHub PR review.',
    previewBody: 'Apply one gate across prompt injection, hidden repo rules, tool scope changes, and generated pull requests.',
    columns: [
      {
        heading: 'Use cases',
        items: [
          {
            title: 'Tool scanning',
            description: 'Catch shell, file-write, branch, and network scope escalation before the tool is used.',
            action: 'coverage',
          },
          {
            title: 'PR gating',
            description: 'Score generated diffs and fail the Check Run when risk crosses the configured threshold.',
            action: 'workflow',
          },
        ],
      },
      {
        heading: 'Coverage',
        items: [
          {
            title: 'Prompt injection',
            description: 'Detect malicious instructions hiding in prompts, markdown specs, and checked-in repo context.',
            action: 'coverage',
          },
          {
            title: 'Agent telemetry',
            description: 'Track which connected coding-agent account opened the PR and what action was processed.',
            action: 'metrics',
          },
        ],
      },
    ],
  },
  {
    key: 'resources',
    label: 'Resources',
    previewTitle: 'Use the same capabilities shown in the README and the running app.',
    previewBody: 'Compliance reporting, policy validation, audit logs, and PR-scanning telemetry are already available in the current repo.',
    columns: [
      {
        heading: 'Learn',
        items: [
          {
            title: 'Architecture',
            description: 'See how PromptShield reviews prompts, tools, configs, and PR diffs using the current detection pipeline.',
            action: 'workflow',
          },
          {
            title: 'Tool scanning',
            description: 'Understand how requested tool permissions and repo context are inspected before execution.',
            action: 'coverage',
          },
        ],
      },
      {
        heading: 'Explore',
        items: [
          {
            title: 'Live demo',
            description: 'Replay a vulnerable coding-agent run immediately in the browser.',
            action: 'demo',
          },
          {
            title: 'Dashboard',
            description: 'Jump into the repo workspace for real PR scan rows, severity mix, and risk trends.',
            action: 'dashboard',
          },
        ],
      },
    ],
  },
  {
    key: 'company',
    label: 'Company',
    previewTitle: 'This product is centered on pull-request review, policy gates, and auditability.',
    previewBody: 'The current app already includes GitHub App review flows, policy validation, compliance exports, and connected coding-agent attribution.',
    columns: [
      {
        heading: 'About',
        items: [
          {
            title: 'Detection metrics',
            description: 'Use the built-in benchmark, static-category counts, and gate metrics as product proof.',
            action: 'metrics',
          },
          {
            title: 'Connected agents',
            description: 'Differentiate Codex, Claude, and Cursor behavior across repositories and recent PRs.',
            action: 'coverage',
          },
        ],
      },
      {
        heading: 'Start',
        items: [
          {
            title: 'Access dashboard',
            description: 'Open the workspace view for PRs, repositories, and policy gates.',
            action: 'dashboard',
          },
          {
            title: 'Try the demo',
            description: 'Run the simulated vulnerable-agent flow from the hero panel.',
            action: 'demo',
          },
        ],
      },
    ],
  },
]

const WORKFLOW_STEPS = [
  {
    title: 'Intercept the agent envelope',
    description:
      'Capture the instruction package, changed files, repo rules, and requested tool scopes before execution or merge.',
    icon: Bot,
  },
  {
    title: 'Scan prompts and tool permissions',
    description:
      'Run static detection plus semantic review to flag prompt injection, hidden instructions, and privilege escalation.',
    icon: Wrench,
  },
  {
    title: 'Gate the PR with evidence',
    description:
      'Attach mapped findings, source snippets, and policy verdicts so unsafe agent output never lands quietly.',
    icon: GitPullRequest,
  },
]

const METRICS = [
  { value: '15+', label: 'detection rules including agent tool, output handling, and RAG security' },
  { value: '14', label: 'structural jailbreak payloads used for adversarial testing' },
  { value: '96%', label: 'F1 on the built-in vulnerable versus safe benchmark' },
  { value: 'CWE + OWASP', label: 'LLM01, LLM05, and LLM06 (2025) mappings attached to each finding for audit' },
]

const COVERAGE_SURFACES = [
  {
    title: 'Prompt and repo instruction scanning',
    body: 'Review agent prompts, hidden repo rules, markdown instructions, and generated system text before they propagate across repositories.',
    detail: 'Catches poisoned context before the next agent consumes it.',
  },
  {
    title: 'Tool scope verification',
    body: 'Evaluate whether an agent is asking for shell, file write, branch, or network access outside the approved workspace contract.',
    detail: 'Flags permission drift before an execution tool is invoked.',
  },
  {
    title: 'PR and diff enforcement',
    body: 'Treat generated commits and pull requests as policy artifacts: score them, annotate evidence, and hold the merge when risk crosses the gate.',
    detail: 'Turns review into a control, not a cleanup step.',
  },
]

const AGENT_ACTIVITY = [
  {
    agent: 'Codex',
    surface: 'Shell execution and repo writes',
    action: 'Flagged when a task attempts out-of-scope file changes or hidden prompt instructions.',
  },
  {
    agent: 'Claude',
    surface: 'Semantic handoffs and review comments',
    action: 'Scanned for indirect injection, policy bypass language, and unsafe remediation suggestions.',
  },
  {
    agent: 'Cursor',
    surface: 'IDE prompts, rules, and generated PRs',
    action: 'Tracked so the origin of an edit and its downstream changes stay visible in one audit trail.',
  },
]

const DEMO_LOG_LINES = [
  '$ promptshield review agent-envelope.json --scope prompts,tools,diff',
  '[ingest] source=cursor target=codex repo=payments-service',
  '[static] prompt and config checks completed across 7 categories',
  '[semantic] suspicious hidden instruction found in .cursor/rules/security.md',
  '[policy] tool scope requests network + write outside approved path',
  '[gate] risk score=82 -> merge blocked and findings attached to PR',
]

const DEMO_FINDINGS = [
  {
    title: 'Indirect prompt injection',
    severity: 'High',
    evidence: 'Repo rule file tries to override secure coding guidance for the downstream agent.',
  },
  {
    title: 'Tool scope escalation',
    severity: 'Critical',
    evidence: 'Requested write and shell access exceed the allowed task boundary.',
  },
  {
    title: 'Unsafe generated diff',
    severity: 'High',
    evidence: 'PR includes policy-bypassing changes that would land without review.',
  },
]

const DEMO_STAGES = [
  {
    label: 'Envelope intake',
    detail: 'Collect prompt, repo rules, and branch metadata.',
  },
  {
    label: 'Static analysis',
    detail: 'Run category checks across prompt, tool, and config surfaces.',
  },
  {
    label: 'Semantic review',
    detail: 'Inspect for hidden instructions and malicious repo context.',
  },
  {
    label: 'Policy gate',
    detail: 'Score the run, attach findings, and decide merge outcome.',
  },
]

function scrollToSection(id, reduced) {
  const section = document.getElementById(id)
  if (!section) return
  section.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' })
}

function Reveal({ children, className = '', delay = 0, reduced }) {
  return (
    <motion.div
      className={className}
      initial={reduced ? { opacity: 1, y: 0 } : { opacity: 0, y: 22 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={reduced ? { duration: 0 } : { duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

function FloatIn({ children, className = '', delay = 0, reduced }) {
  return (
    <motion.div
      className={className}
      initial={reduced ? { opacity: 1, y: 0, scale: 1 } : { opacity: 0, y: 60, scale: 0.92 }}
      whileInView={{ opacity: 1, y: 0, scale: 1 }}
      viewport={{ once: true, amount: 0.15 }}
      transition={
        reduced
          ? { duration: 0 }
          : {
              type: 'spring',
              damping: 22,
              stiffness: 90,
              mass: 0.8,
              delay,
            }
      }
    >
      {children}
    </motion.div>
  )
}

export default function LandingPage({ onEnterDashboard }) {
  const reduced = useReducedMotion()
  const [openMenu, setOpenMenu] = useState(null)
  const [demoStep, setDemoStep] = useState(0)
  const [demoRunId, setDemoRunId] = useState(1)
  const [demoRunning, setDemoRunning] = useState(true)
  const [scrolledPastHero, setScrolledPastHero] = useState(false)
  const navRef = useRef(null)
  const heroRef = useRef(null)
  const activeMenu = NAV_DROPDOWNS.find((item) => item.key === openMenu) || null

  const visibleLines = useMemo(
    () => DEMO_LOG_LINES.slice(0, Math.min(demoStep + 1, DEMO_LOG_LINES.length)),
    [demoStep]
  )
  const progressValue = ((demoStep + 1) / DEMO_LOG_LINES.length) * 100
  const currentStageIndex = demoStep <= 1 ? 0 : demoStep === 2 ? 1 : demoStep <= 4 ? 2 : 3

  const visibleFindings = useMemo(() => {
    if (demoStep < 3) return []
    if (demoStep < 4) return DEMO_FINDINGS.slice(0, 1)
    if (demoStep < 5) return DEMO_FINDINGS.slice(0, 2)
    return DEMO_FINDINGS
  }, [demoStep])

  useEffect(() => {
    const onPointerDown = (event) => {
      if (navRef.current && !navRef.current.contains(event.target)) {
        setOpenMenu(null)
      }
    }

    const onEscape = (event) => {
      if (event.key === 'Escape') setOpenMenu(null)
    }

    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onEscape)

    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onEscape)
    }
  }, [])

  useEffect(() => {
    const onScroll = () => {
      const heroEl = heroRef.current
      if (!heroEl) {
        setScrolledPastHero(window.scrollY > 80)
        return
      }
      const heroBottom = heroEl.getBoundingClientRect().bottom
      setScrolledPastHero(heroBottom < 64)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (!demoRunning) return
    if (demoStep >= DEMO_LOG_LINES.length - 1) {
      setDemoRunning(false)
      return
    }

    const timeout = window.setTimeout(
      () => setDemoStep((current) => current + 1),
      demoStep === 0 ? 500 : 850
    )

    return () => window.clearTimeout(timeout)
  }, [demoRunning, demoStep])

  const restartDemo = () => {
    setOpenMenu(null)
    setDemoRunId((value) => value + 1)
    setDemoStep(0)
    setDemoRunning(true)
  }

  const handleResourceAction = (action) => {
    if (action === 'dashboard') {
      setOpenMenu(null)
      onEnterDashboard()
      return
    }

    if (action === 'demo') {
      restartDemo()
      scrollToSection('hero', reduced)
      return
    }

    setOpenMenu(null)
    scrollToSection(action, reduced)
  }

  return (
    <div className="ibm-landing min-h-screen bg-[#f3f1ea] text-[#16213e]">
      {/* ── Sticky header ─────────────────────────────────────────────── */}
      <header
        className="fixed left-0 right-0 top-0 z-50 transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]"
        style={{
          backgroundColor: scrolledPastHero ? 'rgba(243,241,234,0.82)' : 'rgba(22,33,62,0.60)',
          backdropFilter: 'saturate(180%) blur(20px)',
          WebkitBackdropFilter: 'saturate(180%) blur(20px)',
          borderBottom: scrolledPastHero ? '1px solid rgba(222,113,93,0.18)' : '1px solid transparent',
        }}
      >
        <div className="mx-auto max-w-[1280px] px-6 lg:px-10">
          <div
            ref={navRef}
            className={`relative flex items-center gap-4 rounded-[2px] py-3 transition-all duration-500 lg:flex-nowrap ${
              scrolledPastHero
                ? ''
                : 'my-2 border border-[#de715d]/50 px-5'
            }`}
          >
            <button
              onClick={() => scrollToSection('hero', reduced)}
              className="flex items-center gap-3 text-left"
            >
              <span
                className={`text-[22px] font-semibold tracking-[-0.04em] transition-colors duration-500 ${
                  scrolledPastHero ? 'text-[#16213e]' : 'text-white'
                }`}
                style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
              >
                PromptShield
              </span>
            </button>

            <nav className={`flex flex-wrap items-center gap-1 text-[14px] transition-colors duration-500 lg:ml-12 lg:flex-1 lg:justify-center ${
              scrolledPastHero ? 'text-[#16213e]' : 'text-white'
            }`}>
              {NAV_DROPDOWNS.map((item) => (
                <button
                  key={item.key}
                  onClick={() => setOpenMenu((current) => (current === item.key ? null : item.key))}
                  className={`flex items-center gap-2 rounded-full px-4 py-2 transition-all duration-200 ${
                    scrolledPastHero
                      ? 'hover:bg-[#16213e]/6'
                      : 'hover:bg-white/12'
                  }`}
                  aria-expanded={openMenu === item.key}
                  aria-haspopup="true"
                >
                  <span>{item.label}</span>
                  <ChevronDown className={`h-3.5 w-3.5 transition-transform duration-300 ${openMenu === item.key ? 'rotate-180' : ''}`} />
                </button>
              ))}

              {/* ── Apple-style dropdown ───────────────────────────────── */}
              <AnimatePresence>
                {activeMenu && (
                  <motion.div
                    initial={reduced ? false : { opacity: 0, y: -8, scale: 0.96 }}
                    animate={reduced ? { opacity: 1 } : { opacity: 1, y: 0, scale: 1 }}
                    exit={reduced ? { opacity: 0 } : { opacity: 0, y: -6, scale: 0.97 }}
                    transition={
                      reduced
                        ? { duration: 0 }
                        : { type: 'spring', damping: 26, stiffness: 280, mass: 0.7 }
                    }
                    className="absolute left-0 right-0 top-[calc(100%+8px)] z-40 overflow-hidden rounded-[12px] border border-[#d6d4cf] bg-white text-[#16213e] shadow-[0_24px_80px_rgba(22,33,62,0.22),0_0_0_1px_rgba(0,0,0,0.04)]"
                  >
                    <div className="grid gap-0 lg:grid-cols-[1fr_1fr_320px]">
                      {activeMenu.columns.map((column, colIdx) => (
                        <div
                          key={column.heading}
                          className={`p-6 ${
                            colIdx < activeMenu.columns.length - 1 ? 'border-b border-[#16213e]/6 lg:border-b-0 lg:border-r' : 'border-b border-[#16213e]/6 lg:border-b-0'
                          }`}
                        >
                          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                            {column.heading}
                          </p>
                          <div className="mt-4 space-y-3">
                            {column.items.map((menuItem, itemIdx) => (
                              <motion.button
                                key={menuItem.title}
                                initial={reduced ? false : { opacity: 0, x: -6 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={
                                  reduced
                                    ? { duration: 0 }
                                    : { type: 'spring', damping: 24, stiffness: 200, delay: 0.04 + itemIdx * 0.04 }
                                }
                                onClick={() => handleResourceAction(menuItem.action)}
                                className="block w-full rounded-[8px] p-3 text-left transition-colors duration-150 hover:bg-[#f3f1ea]"
                              >
                                <div className="text-[16px] font-medium text-[#16213e]">{menuItem.title}</div>
                                <div className="mt-1 text-[13px] leading-5 text-[#4b5876]">
                                  {menuItem.description}
                                </div>
                              </motion.button>
                            ))}
                          </div>
                        </div>
                      ))}
                      <div className="ibm-dropdown-preview flex flex-col justify-between rounded-br-[12px] rounded-tr-[12px] p-6">
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#f3cabf]">
                            {activeMenu.label}
                          </p>
                          <div className="mt-4 text-[26px] font-light leading-[1.08] text-white">
                            {activeMenu.previewTitle}
                          </div>
                          <p className="mt-3 max-w-[26ch] text-[14px] leading-6 text-white/80">
                            {activeMenu.previewBody}
                          </p>
                        </div>
                        <button
                          onClick={restartDemo}
                          className="mt-6 inline-flex w-fit items-center gap-2 rounded-[8px] border border-[#de715d]/70 bg-[#de715d] px-4 py-2.5 text-[14px] font-medium text-white transition hover:bg-[#cb624f]"
                        >
                          Try with vulnerable agent
                          <ArrowRight className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </nav>

            <div className="ml-auto flex items-center gap-3">
              <button
                onClick={onEnterDashboard}
                className={`px-4 py-2 text-[14px] transition-colors duration-500 ${
                  scrolledPastHero ? 'text-[#16213e] hover:text-[#de715d]' : 'text-white hover:text-[#f3cabf]'
                }`}
              >
                Log in
              </button>
              <button
                onClick={onEnterDashboard}
                className={`rounded-full px-5 py-2.5 text-[14px] font-medium transition-all duration-500 ${
                  scrolledPastHero
                    ? 'border border-[#16213e] bg-[#16213e] text-white hover:bg-[#233050]'
                    : 'border border-white/30 bg-white/10 text-white hover:bg-white/18'
                }`}
                style={{
                  backdropFilter: scrolledPastHero ? 'none' : 'blur(8px)',
                  WebkitBackdropFilter: scrolledPastHero ? 'none' : 'blur(8px)',
                }}
              >
                Access dashboard
              </button>
            </div>
          </div>
        </div>
      </header>

      <section ref={heroRef} className="border-b border-[#de715d]/40 bg-[#16213e] text-white">
        <div className="mx-auto max-w-[1280px] px-6 pb-18 pt-6 lg:px-10">

          <div id="hero" className="pb-4 pt-20">
            <Reveal reduced={reduced} className="mx-auto max-w-[1140px] text-center">
              <h1 className="font-pixel-display mx-auto max-w-[15ch] text-[clamp(2.6rem,6vw,5.6rem)] leading-[1.14] tracking-[0.035em] text-[#f3f1ea]">
                Secure AI agents before dangerous code merges
              </h1>
              <p className="mx-auto mt-8 max-w-[64ch] text-[18px] leading-8 text-[#d6d8e1]">
                PromptShield scans agent prompts, repo instructions, tool scopes, and generated pull requests before downstream agents execute or a risky diff lands on main.
              </p>
              <p className="mx-auto mt-3 max-w-[52ch] text-[15px] leading-7 text-[#b8bece]">
                Built for teams using Codex, Claude, Cursor, and internal coding agents across shared repositories.
              </p>

              <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
                <button
                  onClick={restartDemo}
                  className="inline-flex items-center gap-2 border border-[#de715d] bg-[#de715d] px-5 py-3 text-[15px] font-medium text-white transition hover:bg-[#cb624f]"
                >
                  Try with vulnerable agent
                  <ArrowRight className="h-4 w-4" />
                </button>
                <button
                  onClick={onEnterDashboard}
                  className="inline-flex items-center gap-2 border border-[#f3f1ea]/26 bg-[#f3f1ea] px-5 py-3 text-[15px] font-medium text-[#16213e] transition hover:bg-white"
                >
                  Access dashboard
                </button>
                <span className="text-[13px] text-[#d1bcb5]">
                  Starts immediately in the browser. No backend required for the demo.
                </span>
              </div>

              <div className="mt-12 flex flex-wrap justify-center gap-3 text-[12px] font-medium uppercase tracking-[0.14em] text-[#f0ddd7]">
                {['Codex', 'Claude', 'Cursor', 'GitHub PRs', 'Tool scopes'].map((item) => (
                  <span key={item} className="border border-[#de715d]/60 bg-[#233050] px-3 py-2">
                    {item}
                  </span>
                ))}
              </div>
            </Reveal>

            <Reveal reduced={reduced} delay={0.08} className="mt-12">
              <div className="overflow-hidden border border-[#de715d]/55 bg-[#f5f3ee] shadow-[0_30px_80px_rgba(9,16,34,0.18)]">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#de715d]/35 bg-[#16213e] px-5 py-4 text-white">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#f3cabf]">
                      Live run
                    </div>
                    <div className="mt-1 text-[18px] font-medium">
                      Vulnerable agent handoff simulation
                    </div>
                  </div>
                  <button
                    onClick={restartDemo}
                    className="inline-flex items-center gap-2 border border-[#de715d]/60 bg-[#de715d] px-4 py-2 text-[13px] font-medium text-white transition hover:bg-[#cb624f]"
                  >
                    <span className={`ibm-live-dot ${demoRunning ? 'is-active' : ''}`} />
                    {demoRunning ? 'Running' : 'Replay'}
                  </button>
                </div>

                <div className="grid gap-0 lg:grid-cols-[1.15fr_0.85fr]">
                  <div className="ibm-terminal-panel border-b border-[#de715d]/30 px-5 py-5 lg:border-b-0 lg:border-r lg:border-r-[#de715d]/30">
                    <div className="flex items-center justify-between text-[12px] text-[#f3cabf]">
                      <div className="inline-flex items-center gap-2">
                        <TerminalSquare className="h-4 w-4" />
                        <span>scan-session-{demoRunId.toString().padStart(3, '0')}</span>
                      </div>
                      <span>local preview</span>
                    </div>

                    <div className="mt-4 space-y-3">
                      <div className="flex items-center justify-between text-[11px] uppercase tracking-[0.16em] text-[#f3cabf]">
                        <span>Execution progress</span>
                        <span>{Math.round(progressValue)}%</span>
                      </div>
                      <div className="h-2 overflow-hidden border border-[#de715d]/20 bg-black/20">
                        <motion.div
                          key={demoRunId}
                          initial={{ width: 0 }}
                          animate={{ width: `${progressValue}%` }}
                          transition={{ duration: reduced ? 0 : 0.45, ease: 'easeOut' }}
                          className="h-full bg-[#de715d]"
                        />
                      </div>
                      <div className="grid gap-2 sm:grid-cols-2">
                        {DEMO_STAGES.map((stage, index) => {
                          const state =
                            index < currentStageIndex
                              ? 'done'
                              : index === currentStageIndex
                                ? 'active'
                                : 'pending'
                          return (
                            <motion.div
                              key={stage.label}
                              initial={false}
                              animate={{
                                borderColor:
                                  state === 'done'
                                    ? 'rgba(222,113,93,0.36)'
                                    : state === 'active'
                                      ? 'rgba(243,202,191,0.52)'
                                      : 'rgba(222,113,93,0.14)',
                                backgroundColor:
                                  state === 'done'
                                    ? 'rgba(255,255,255,0.05)'
                                    : state === 'active'
                                      ? 'rgba(222,113,93,0.14)'
                                      : 'rgba(255,255,255,0.02)',
                              }}
                              className="border px-3 py-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <span className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#f3cabf]">
                                  {stage.label}
                                </span>
                                <span
                                  className={`h-2.5 w-2.5 rounded-full ${
                                    state === 'done'
                                      ? 'bg-[#de715d]'
                                      : state === 'active'
                                        ? 'bg-[#f3cabf]'
                                        : 'bg-white/20'
                                  }`}
                                />
                              </div>
                              <p className="mt-2 text-[12px] leading-5 text-[#c7d0e5]">
                                {stage.detail}
                              </p>
                            </motion.div>
                          )
                        })}
                      </div>
                    </div>

                    <div
                      className="ibm-terminal-feed mt-5 min-h-[294px] space-y-3 text-[14px] leading-6 text-[#d7dcea]"
                      style={{ fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}
                    >
                      {!reduced && demoRunning && (
                        <motion.div
                          key={`sweep-${demoRunId}-${demoStep}`}
                          initial={{ y: -40, opacity: 0 }}
                          animate={{ y: 340, opacity: [0, 0.28, 0] }}
                          transition={{ duration: 1.3, ease: 'easeInOut', repeat: Infinity }}
                          className="ibm-terminal-sweep"
                        />
                      )}
                      {visibleLines.map((line, index) => {
                        const isCommand = index === 0
                        const isAlert = line.includes('suspicious') || line.includes('risk score')
                        const color = isCommand
                          ? 'text-[#f3cabf]'
                          : isAlert
                            ? 'text-[#ffb8a9]'
                            : 'text-[#d7dcea]'

                        return (
                          <motion.div
                            key={`${demoRunId}-${index}`}
                            initial={reduced ? false : { opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: reduced ? 0 : 0.22 }}
                            className={`ibm-terminal-line ${color} ${
                              index === visibleLines.length - 1 && demoRunning ? 'ibm-terminal-line-active' : ''
                            }`}
                          >
                            {line}
                          </motion.div>
                        )
                      })}
                      {!reduced && demoRunning && (
                        <motion.span
                          animate={{ opacity: [0.2, 1, 0.2] }}
                          transition={{ repeat: Infinity, duration: 1.1 }}
                          className="inline-block h-[18px] w-[10px] bg-[#de715d]"
                        />
                      )}
                    </div>
                  </div>

                  <div className="bg-[#f5f3ee] px-5 py-5">
                    <div className="grid gap-4">
                      <motion.div
                        initial={false}
                        animate={{
                          borderColor: demoRunning ? 'rgba(222,113,93,0.4)' : 'rgba(88,83,42,0.36)',
                          boxShadow: demoRunning
                            ? '0 0 0 1px rgba(222,113,93,0.05), 0 18px 36px rgba(22,33,62,0.08)'
                            : '0 0 0 1px rgba(88,83,42,0.03), 0 12px 24px rgba(22,33,62,0.05)',
                        }}
                        className="border bg-white px-4 py-4"
                      >
                        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                          Policy verdict
                        </div>
                        <div className="mt-2 flex items-center justify-between gap-3">
                          <div className="text-[26px] font-light text-[#16213e]">Blocked before merge</div>
                          <span className="border border-[#de715d]/30 bg-[#fff1ec] px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-[#b84d39]">
                            Score 82
                          </span>
                        </div>
                        <p className="mt-2 text-[14px] leading-6 text-[#4b5876]">
                          Unsafe prompts, expanded tool scopes, and risky diffs are grouped into one enforcement decision.
                        </p>
                      </motion.div>

                      <div>
                        <div className="flex items-center justify-between gap-3">
                          <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                            Findings attached to the merge gate
                          </div>
                          <div className="text-[11px] font-medium text-[#63708d]">
                            {visibleFindings.length}/{DEMO_FINDINGS.length} surfaced
                          </div>
                        </div>
                        <div className="mt-4 space-y-3">
                          {visibleFindings.map((finding) => (
                            <motion.div
                              key={finding.title}
                              initial={reduced ? false : { opacity: 0, x: 18, scale: 0.98 }}
                              animate={{ opacity: 1, x: 0, scale: 1 }}
                              transition={{ duration: reduced ? 0 : 0.25 }}
                              className="border border-[#de715d]/35 bg-white p-4"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <div className="text-[15px] font-medium text-[#16213e]">{finding.title}</div>
                                <span
                                  className={`px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${
                                    finding.severity === 'Critical'
                                      ? 'bg-[#ffe7e1] text-[#b84d39]'
                                      : 'bg-[#f3ede2] text-[#58532a]'
                                  }`}
                                >
                                  {finding.severity}
                                </span>
                              </div>
                              <p className="mt-2 text-[14px] leading-6 text-[#4b5876]">{finding.evidence}</p>
                            </motion.div>
                          ))}
                          {!visibleFindings.length && (
                            <div className="border border-dashed border-[#de715d]/50 bg-white px-4 py-6 text-[14px] text-[#63708d]">
                              Findings appear as the simulated run inspects the vulnerable agent envelope.
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      <section id="workflow" className="border-b border-[#de715d]/26 bg-[#f3f1ea]">
        <div className="mx-auto max-w-[1280px] px-6 py-20 lg:px-10">
          <Reveal reduced={reduced} className="max-w-[760px]">
            <p className="text-[12px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
              Workflow
            </p>
            <h2 className="mt-4 text-[42px] font-light leading-[1.02] tracking-[-0.04em] text-[#16213e]">
              One review layer between coding agents and production repos.
            </h2>
            <p className="mt-4 max-w-[62ch] text-[17px] leading-8 text-[#4b5876]">
              Instead of trusting each agent run in isolation, PromptShield evaluates the full handoff package and turns risky automation into an explicit gate.
            </p>
          </Reveal>

          <div className="mt-10 grid gap-5 lg:grid-cols-3">
            {WORKFLOW_STEPS.map((step, index) => {
              const Icon = step.icon

              return (
                <FloatIn key={step.title} reduced={reduced} delay={index * 0.12}>
                  <motion.article
                    className="h-full border border-[#de715d]/30 bg-white p-6"
                    whileHover={reduced ? {} : { y: -6, scale: 1.015, boxShadow: '0 20px 60px rgba(22,33,62,0.10)' }}
                    transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[12px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                        0{index + 1}
                      </span>
                      <Icon className="h-5 w-5 text-[#de715d]" />
                    </div>
                    <h3 className="mt-8 text-[24px] font-medium leading-[1.15] tracking-[-0.03em] text-[#16213e]">
                      {step.title}
                    </h3>
                    <p className="mt-4 text-[15px] leading-7 text-[#4b5876]">{step.description}</p>
                  </motion.article>
                </FloatIn>
              )
            })}
          </div>
        </div>
      </section>

      <section id="coverage" className="border-b border-[#de715d]/26 bg-white">
        <div className="mx-auto max-w-[1280px] px-6 py-20 lg:px-10">
          <div className="grid gap-10 lg:grid-cols-[0.88fr_1.12fr]">
            <Reveal reduced={reduced} className="max-w-[520px]">
              <p className="text-[12px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                Tool scanning
              </p>
              <h2 className="mt-4 text-[40px] font-light leading-[1.02] tracking-[-0.04em] text-[#16213e]">
                Scan the full execution surface, not just the prompt text.
              </h2>
              <p className="mt-5 text-[17px] leading-8 text-[#4b5876]">
                Coding agents do not fail only at the prompt layer. Risk travels through hidden repo instructions, changed configs, widened tool scopes, and generated pull requests.
              </p>
              <div className="mt-8 space-y-4">
                {COVERAGE_SURFACES.map((surface) => (
                  <div key={surface.title} className="border-l-2 border-[#de715d] pl-4">
                    <div className="text-[20px] font-medium text-[#16213e]">{surface.title}</div>
                    <p className="mt-2 text-[15px] leading-7 text-[#4b5876]">{surface.body}</p>
                    <p className="mt-2 text-[14px] leading-6 text-[#58532a]">{surface.detail}</p>
                  </div>
                ))}
              </div>
            </Reveal>

            <Reveal reduced={reduced} delay={0.08}>
              <div className="overflow-hidden border border-[#de715d]/30 bg-[#f7f8fb]">
                <div className="grid border-b border-[#de715d]/26 bg-[#e1e3eb] px-5 py-4 text-[12px] font-semibold uppercase tracking-[0.16em] text-[#58532a] lg:grid-cols-[180px_1fr_180px]">
                  <span>Surface</span>
                  <span>What PromptShield reads</span>
                  <span>Outcome</span>
                </div>
                <div className="divide-y divide-[#ddd7d1]">
                  {[
                    {
                      surface: 'Prompt envelope',
                      read: 'Task prompt, handoff summary, branch target, and generated system instructions.',
                      outcome: 'Injection and policy bypass signals scored before execution.',
                      icon: Bot,
                    },
                    {
                      surface: 'Tool scopes',
                      read: 'Shell, file write, branch, and network permissions requested by the agent.',
                      outcome: 'Escalations blocked when the task boundary is exceeded.',
                      icon: Wrench,
                    },
                    {
                      surface: 'Repo context',
                      read: 'Cursor rules, markdown specs, config files, and hidden instructions checked into source.',
                      outcome: 'Poisoned context caught before another agent consumes it.',
                      icon: FileCode2,
                    },
                    {
                      surface: 'Generated PR',
                      read: 'Changed files, diff hunks, comments, and merge metadata.',
                      outcome: 'Unsafe code changes map directly to a merge gate decision.',
                      icon: GitPullRequest,
                    },
                  ].map((row) => {
                    const Icon = row.icon

                    return (
                      <div key={row.surface} className="grid gap-4 px-5 py-5 lg:grid-cols-[180px_1fr_180px] lg:items-start">
                        <div className="flex items-center gap-3 text-[15px] font-medium text-[#16213e]">
                          <Icon className="h-4 w-4 text-[#de715d]" />
                          <span>{row.surface}</span>
                        </div>
                        <p className="text-[15px] leading-7 text-[#4b5876]">{row.read}</p>
                        <p className="text-[14px] leading-6 text-[#58532a]">{row.outcome}</p>
                      </div>
                    )
                  })}
                </div>
              </div>

              <div className="mt-5 grid gap-4 md:grid-cols-3">
                {AGENT_ACTIVITY.map((item, index) => (
                  <FloatIn key={item.agent} reduced={reduced} delay={index * 0.1}>
                    <motion.div
                      className="border border-[#de715d]/30 bg-[#f3f1ea] p-5"
                      whileHover={reduced ? {} : { y: -4, boxShadow: '0 16px 48px rgba(22,33,62,0.08)' }}
                      transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                    >
                      <div className="flex items-center justify-between">
                        <div className="text-[20px] font-medium text-[#16213e]">{item.agent}</div>
                        <ShieldAlert className="h-4 w-4 text-[#de715d]" />
                      </div>
                      <div className="mt-3 text-[13px] font-semibold uppercase tracking-[0.14em] text-[#58532a]">
                        {item.surface}
                      </div>
                      <p className="mt-3 text-[14px] leading-6 text-[#4b5876]">{item.action}</p>
                    </motion.div>
                  </FloatIn>
                ))}
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      <section id="metrics" className="border-b border-[#de715d]/26 bg-[#e1e3eb]">
        <div className="mx-auto max-w-[1280px] px-6 py-20 lg:px-10">
          <Reveal reduced={reduced} className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-[760px]">
              <p className="text-[12px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                Metrics
              </p>
              <h2 className="mt-4 text-[40px] font-light leading-[1.02] tracking-[-0.04em] text-[#16213e]">
                Hard numbers from the same pipeline that runs on every PR.
              </h2>
            </div>
            <button
              onClick={onEnterDashboard}
              className="inline-flex items-center gap-2 border border-[#16213e] bg-white px-5 py-3 text-[15px] font-medium text-[#16213e] transition hover:border-[#de715d] hover:text-[#de715d]"
            >
              Open dashboard
              <ArrowRight className="h-4 w-4" />
            </button>
          </Reveal>

          <div className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {METRICS.map((metric, index) => (
              <FloatIn key={metric.value} reduced={reduced} delay={index * 0.08}>
                <motion.div
                  className="border border-[#de715d]/28 bg-white p-6"
                  whileHover={reduced ? {} : { y: -4, boxShadow: '0 16px 48px rgba(22,33,62,0.08)' }}
                  transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                >
                  <div
                    className="text-[clamp(2.4rem,4vw,3.4rem)] font-light leading-none tracking-[-0.05em] text-[#16213e]"
                    style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
                  >
                    {metric.value}
                  </div>
                  <p className="mt-4 text-[14px] leading-7 text-[#4b5876]">{metric.label}</p>
                </motion.div>
              </FloatIn>
            ))}
          </div>
        </div>
      </section>

      <section className="bg-[#16213e] text-white">
        <div className="mx-auto flex max-w-[1280px] flex-col gap-6 px-6 py-16 lg:flex-row lg:items-center lg:justify-between lg:px-10">
          <div className="max-w-[760px]">
            <p className="text-[12px] font-semibold uppercase tracking-[0.16em] text-[#f3cabf]">
              Start with the browser demo
            </p>
            <h2 className="mt-4 text-[38px] font-light leading-[1.04] tracking-[-0.04em] text-white">
              See a vulnerable agent run get blocked before it becomes a merge problem.
            </h2>
            <p className="mt-4 text-[16px] leading-8 text-white/74">
              The landing page demo is local-only. When you want real scan history, PR telemetry, and repo-level analytics, the dashboard is one click away.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              onClick={restartDemo}
              className="inline-flex items-center gap-2 border border-[#de715d] bg-[#de715d] px-5 py-3 text-[15px] font-medium text-white transition hover:bg-[#cb624f]"
            >
              Try with vulnerable agent
              <ArrowRight className="h-4 w-4" />
            </button>
            <button
              onClick={onEnterDashboard}
              className="inline-flex items-center gap-2 border border-[#f3f1ea]/24 bg-transparent px-5 py-3 text-[15px] font-medium text-white transition hover:bg-white/10"
            >
              Access dashboard
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}
