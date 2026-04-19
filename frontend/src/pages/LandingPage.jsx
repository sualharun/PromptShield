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
    previewBody: 'PromptShield runs 7 static-rule categories plus a semantic audit, scores the result, and attaches evidence to the PR gate.',
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
  { value: '7', label: 'static rule categories reviewed in parallel' },
  { value: '14', label: 'structural jailbreak payloads used for adversarial testing' },
  { value: '96%', label: 'F1 on the built-in vulnerable versus safe benchmark' },
  { value: 'CWE + OWASP', label: 'mappings attached to each finding for policy and audit' },
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

export default function LandingPage({ onEnterDashboard }) {
  const reduced = useReducedMotion()
  const [openMenu, setOpenMenu] = useState(null)
  const [demoStep, setDemoStep] = useState(0)
  const [demoRunId, setDemoRunId] = useState(1)
  const [demoRunning, setDemoRunning] = useState(true)
  const navRef = useRef(null)
  const activeMenu = NAV_DROPDOWNS.find((item) => item.key === openMenu) || null

  const visibleLines = useMemo(
    () => DEMO_LOG_LINES.slice(0, Math.min(demoStep + 1, DEMO_LOG_LINES.length)),
    [demoStep]
  )

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
      <section className="border-b border-[#de715d]/40 bg-[#16213e] text-white">
        <div className="mx-auto max-w-[1280px] px-6 pb-18 pt-6 lg:px-10">
          <header className="relative z-30 rounded-[2px] border border-[#de715d]/55 bg-[#16213e] text-white shadow-[0_20px_48px_rgba(9,16,34,0.22)]">
            <div
              ref={navRef}
              className="relative flex flex-wrap items-center gap-4 px-5 py-4 lg:flex-nowrap lg:px-7"
            >
              <button
                onClick={() => scrollToSection('hero', reduced)}
                className="flex items-center gap-3 text-left"
              >
                <span
                  className="text-[22px] font-semibold tracking-[-0.04em]"
                  style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
                >
                  PromptShield
                </span>
              </button>

              <nav className="flex flex-wrap items-center gap-1 text-[14px] text-white/82 lg:ml-12 lg:flex-1 lg:justify-center">
                {NAV_DROPDOWNS.map((item) => (
                  <button
                    key={item.key}
                    onClick={() => setOpenMenu((current) => (current === item.key ? null : item.key))}
                    className="flex items-center gap-2 rounded-[2px] px-4 py-2 transition hover:bg-white/8 hover:text-white"
                    aria-expanded={openMenu === item.key}
                    aria-haspopup="true"
                  >
                    <span>{item.label}</span>
                    <ChevronDown className={`h-4 w-4 transition ${openMenu === item.key ? 'rotate-180' : ''}`} />
                  </button>
                ))}
                <AnimatePresence>
                  {activeMenu && (
                    <motion.div
                      initial={reduced ? false : { opacity: 0, y: 10 }}
                      animate={reduced ? { opacity: 1 } : { opacity: 1, y: 0 }}
                      exit={reduced ? { opacity: 0 } : { opacity: 0, y: 8 }}
                      transition={{ duration: reduced ? 0 : 0.18 }}
                      className="absolute left-5 right-5 top-[calc(100%+18px)] z-40 w-auto rounded-[2px] border border-[#de715d]/45 bg-[#f5f3ee] text-[#16213e] shadow-[0_32px_80px_rgba(9,16,34,0.26)] lg:left-7 lg:right-7"
                    >
                      <div className="grid gap-0 lg:grid-cols-[1fr_1fr_320px]">
                        {activeMenu.columns.map((column, index) => (
                          <div
                            key={column.heading}
                            className={`border-b border-[#d6d4cf] p-6 lg:border-b-0 ${
                              index < activeMenu.columns.length - 1 ? 'lg:border-r' : ''
                            }`}
                          >
                            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                              {column.heading}
                            </p>
                            <div className="mt-4 space-y-4">
                              {column.items.map((menuItem) => (
                                <button
                                  key={menuItem.title}
                                  onClick={() => handleResourceAction(menuItem.action)}
                                  className="block w-full text-left transition hover:text-[#de715d]"
                                >
                                  <div className="text-[18px] font-medium text-[#16213e]">{menuItem.title}</div>
                                  <div className="mt-1 text-[14px] leading-6 text-[#4b5876]">
                                    {menuItem.description}
                                  </div>
                                </button>
                              ))}
                            </div>
                          </div>
                        ))}
                        <div className="ibm-dropdown-preview flex flex-col justify-between p-6">
                          <div>
                            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#f3cabf]">
                              {activeMenu.label}
                            </p>
                            <div className="mt-4 text-[28px] font-light leading-[1.08] text-white">
                              {activeMenu.previewTitle}
                            </div>
                            <p className="mt-3 max-w-[26ch] text-[14px] leading-6 text-white/80">
                              {activeMenu.previewBody}
                            </p>
                          </div>
                          <button
                            onClick={restartDemo}
                            className="mt-6 inline-flex w-fit items-center gap-2 border border-[#de715d]/70 bg-[#de715d] px-4 py-3 text-[14px] font-medium text-white transition hover:bg-[#cb624f]"
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
                  className="px-4 py-2 text-[14px] text-white/86 transition hover:text-white"
                >
                  Log in
                </button>
                <button
                  onClick={onEnterDashboard}
                  className="border border-[#de715d] bg-[#de715d] px-5 py-3 text-[14px] font-medium text-white transition hover:bg-[#cb624f]"
                >
                  Access dashboard
                </button>
              </div>
            </div>
          </header>

          <div id="hero" className="pb-4 pt-14">
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

                    <div
                      className="mt-5 min-h-[294px] space-y-3 text-[14px] leading-6 text-[#d7dcea]"
                      style={{ fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}
                    >
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
                            className={`ibm-terminal-line ${color}`}
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
                      <div className="border border-[#de715d]/40 bg-white px-4 py-4">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                          Policy verdict
                        </div>
                        <div className="mt-2 text-[26px] font-light text-[#16213e]">Blocked before merge</div>
                        <p className="mt-2 text-[14px] leading-6 text-[#4b5876]">
                          Unsafe prompts, expanded tool scopes, and risky diffs are grouped into one enforcement decision.
                        </p>
                      </div>

                      <div>
                        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
                          Findings attached to the merge gate
                        </div>
                        <div className="mt-4 space-y-3">
                          {visibleFindings.map((finding) => (
                            <div key={finding.title} className="border border-[#de715d]/35 bg-white p-4">
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
                            </div>
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
                <Reveal key={step.title} reduced={reduced} delay={index * 0.06}>
                  <article className="h-full border border-[#de715d]/30 bg-white p-6">
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
                  </article>
                </Reveal>
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
                {AGENT_ACTIVITY.map((item) => (
                  <div key={item.agent} className="border border-[#de715d]/30 bg-[#f3f1ea] p-5">
                    <div className="flex items-center justify-between">
                      <div className="text-[20px] font-medium text-[#16213e]">{item.agent}</div>
                      <ShieldAlert className="h-4 w-4 text-[#de715d]" />
                    </div>
                    <div className="mt-3 text-[13px] font-semibold uppercase tracking-[0.14em] text-[#58532a]">
                      {item.surface}
                    </div>
                    <p className="mt-3 text-[14px] leading-6 text-[#4b5876]">{item.action}</p>
                  </div>
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
                Built around the real detection system already in this repo.
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
              <Reveal key={metric.value} reduced={reduced} delay={index * 0.04}>
                <div className="border border-[#de715d]/28 bg-white p-6">
                  <div
                    className="text-[clamp(2.4rem,4vw,3.4rem)] font-light leading-none tracking-[-0.05em] text-[#16213e]"
                    style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
                  >
                    {metric.value}
                  </div>
                  <p className="mt-4 text-[14px] leading-7 text-[#4b5876]">{metric.label}</p>
                </div>
              </Reveal>
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
