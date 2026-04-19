import { motion, useReducedMotion } from 'framer-motion'
import { useEffect, useState } from 'react'
import { ArrowRight, ChevronRight, Clock3, Download, ShieldCheck, Sparkles } from 'lucide-react'

const TRUST_MARKS = [
  'GitHub PR Reviews',
  'OWASP LLM Top 10',
  'CWE Mapping',
  'Policy-as-Code',
  'Claude Audit',
  'Audit Trail',
]

const WORKFLOW_CARDS = [
  {
    id: 'review',
    badge: 'Hours back, every week',
    title: 'Pull-request review, fully automated',
    description:
      'Scan risky prompt and agent code before merge with static rules, semantic audit, and repo-level gates.',
    visual: 'steps',
  },
  {
    id: 'scoring',
    badge: 'Risk score from 0 to 100',
    title: 'Scoring as a repeatable system',
    description:
      'Return ranked findings with severity, confidence, evidence snippets, and concrete remediation guidance.',
    visual: 'table',
  },
  {
    id: 'redteam',
    badge: '14 payloads across 6 categories',
    title: 'Automated jailbreak testing your team can trust',
    description:
      'Probe indirect injection, prompt leakage, and unsafe tool behavior with structural attack simulations.',
    visual: 'clauses',
  },
  {
    id: 'release',
    badge: 'CSV, PDF, and policy gates',
    title: 'Governance outputs traceable to source',
    description:
      'Export audit-ready reports, policy decisions, and persistent scan history for security and compliance teams.',
    visual: 'files',
  },
]

const METRICS = [
  {
    stat: '7',
    label: 'Static rule categories run in parallel before the semantic audit begins',
    badge: 'Layered detection',
    before: 'Manual review',
    after: 'Automated baseline',
    beforeNote: 'Reviewer-dependent checks and inconsistent coverage.',
    afterNote: 'Detectors fan out immediately before deeper semantic analysis.',
  },
  {
    stat: '14',
    label: 'Structural jailbreak payloads used to pressure test flagged prompts',
    badge: 'Jailbreak engine',
    before: 'Ad hoc tests',
    after: 'Repeatable coverage',
    beforeNote: 'One-off experiments with no persistent benchmark.',
    afterNote: 'A fixed attack pack keeps release testing measurable.',
  },
  {
    stat: '96%',
    label: 'F1 on the built-in 100-sample benchmark for vulnerable vs safe inputs',
    badge: 'Evaluation benchmark',
    before: 'Guesswork',
    after: 'Measured quality',
    beforeNote: 'Security quality judged from intuition and spot checks.',
    afterNote: 'Built-in benchmark makes model and rule changes trackable.',
  },
]

const TESTIMONIALS = [
  {
    label: 'Shift-left review',
    metric: 'Before merge',
    quote:
      'PromptShield is built to catch risky prompt and agent changes during pull request review instead of waiting for runtime monitoring after deploy.',
    name: 'README',
    title: 'Product positioning',
  },
  {
    label: 'Open-source posture',
    metric: 'Self-hostable',
    quote:
      'The repo already ships scanning, compliance reporting, PM analytics, policy validation, dependency CVE checks, and GitHub App review flows in one stack.',
    name: 'README',
    title: 'Current feature set',
  },
]

const RESULTS = [
  {
    workflow: 'PR prompt review',
    beforeLabel: 'Where risk is found',
    before: 'Late in QA',
    afterLabel: 'Where risk is found',
    after: 'During code review',
    result: 'Higher-confidence blocking before merge',
  },
  {
    workflow: 'Semantic + static analysis',
    beforeLabel: 'Coverage',
    before: 'Regex only',
    afterLabel: 'Coverage',
    after: 'Layered analysis',
    result: 'Findings sorted by severity and confidence',
  },
  {
    workflow: '.promptshield.yml policy',
    beforeLabel: 'Repo gate',
    before: 'One-size-fits-all',
    afterLabel: 'Repo gate',
    after: 'Configurable',
    result: 'Thresholds, overrides, and ignore rules per repo',
  },
  {
    workflow: 'History and audit trail',
    beforeLabel: 'Evidence',
    before: 'Transient',
    afterLabel: 'Evidence',
    after: 'Persistent',
    result: 'Last 10 scans and immutable-style activity log',
  },
  {
    workflow: 'Compliance exports',
    beforeLabel: 'Governance handoff',
    before: 'Manual',
    afterLabel: 'Governance handoff',
    after: 'Exportable',
    result: 'CSV and PDF reports for audit workflows',
  },
  {
    workflow: 'Cross-repo analytics',
    beforeLabel: 'Pattern detection',
    before: 'Siloed',
    afterLabel: 'Pattern detection',
    after: 'Shared trends',
    result: 'Recurring vuln types across repositories',
  },
]

const OUTCOMES = [
  {
    title: 'GitHub App posts inline review comments only on added diff lines',
    stat: 'PR',
    detail: 'review bot flow baked into the backend and dashboard',
  },
  {
    title: 'Compliance dashboard maps findings directly to CWE and OWASP LLM categories',
    stat: 'CWE',
    detail: 'governance view already wired into the frontend',
  },
  {
    title: 'PM analytics track blocked PRs, author leaderboards, and remediation deltas',
    stat: 'PM',
    detail: 'role-gated analytics for engineering leadership',
  },
]

const SECURITY_BADGES = ['SOC 2', 'GDPR', 'Audit Logs', 'RBAC', 'Zero Training']

const FOOTER_COLUMNS = [
  {
    heading: 'Platform',
    links: ['Overview', 'Workflows', 'Knowledge Hubs', 'Reports', 'Integrations', 'Automation'],
  },
  {
    heading: 'Workflows',
    links: ['Review prompts', 'Red-team releases', 'Search incidents', 'Create evidence', 'Resolve findings', 'Run experiments'],
  },
  {
    heading: 'Resources',
    links: ['Insights', 'News', 'Events', 'Customer stories', 'Documentation', 'Pricing'],
  },
  {
    heading: 'Security',
    links: ['Trust Center', 'Policy validation', 'Compliance exports', 'Audit trail', 'Role-based auth'],
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
      initial={reduced ? { opacity: 1, y: 0 } : { opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.18 }}
      transition={reduced ? { duration: 0 } : { duration: 0.55, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

function LiquidButton({ children, onClick, tone = 'light', icon = false }) {
  const toneClass = tone === 'dark' ? 'landing-ibm-secondary' : 'landing-ibm-button'

  return (
    <button
      onClick={onClick}
      className={`liquid-button inline-flex items-center gap-2 border px-5 py-3 text-sm font-semibold tracking-[-0.02em] transition-colors duration-200 ${toneClass}`}
    >
      <span>{children}</span>
      {icon && <ArrowRight className="h-4 w-4" strokeWidth={2.2} />}
    </button>
  )
}

function GlassChip({ children, className = '' }) {
  return (
    <div
      className={`glass-chip inline-flex items-center gap-1.5 border border-white/10 bg-white/6 px-3 py-1.5 text-[11px] font-medium text-white/62 ${className}`}
    >
      <Clock3 className="h-3.5 w-3.5" />
      <span>{children}</span>
    </div>
  )
}

function HeroTrustRow({ reduced }) {
  return (
    <Reveal reduced={reduced} delay={0.24}>
      <div className="mt-12 grid gap-4 border-t border-white/10 pt-6 text-white/96 sm:grid-cols-3 xl:grid-cols-6">
        {TRUST_MARKS.map((mark) => (
          <div
            key={mark}
            className="text-center text-[13px] font-semibold tracking-[0.04em] text-white/80 sm:text-left"
          >
            {mark}
          </div>
        ))}
      </div>
    </Reveal>
  )
}

function TerminalLogBlock({ reduced }) {
  const steps = [
    {
      stage: 'Webhook',
      status: 'received',
      line: '[13:42:03] github webhook accepted :: PR #184 :: branch=feature/prompt-router',
    },
    {
      stage: 'Diff',
      status: 'indexing',
      line: '[13:42:05] changed files indexed :: prompts/reviewer.ts :: agents/policy.ts',
    },
    {
      stage: 'Static',
      status: 'running',
      line: '[13:42:06] static detectors online :: DIRECT_INJECTION :: ROLE_CONFUSION :: DATA_LEAKAGE',
    },
    {
      stage: 'Semantic',
      status: 'streaming',
      line: '[13:42:08] claude semantic audit attached :: evidence extraction in progress',
    },
    {
      stage: 'Policy',
      status: 'gating',
      line: '[13:42:10] .promptshield.yml loaded :: threshold=70 :: block_on=critical,high',
    },
    {
      stage: 'Report',
      status: 'publishing',
      line: '[13:42:12] github review + csv/pdf evidence pack queued for export',
    },
  ]

  const [visibleCount, setVisibleCount] = useState(reduced ? steps.length : 3)
  const [cycle, setCycle] = useState(0)

  useEffect(() => {
    if (reduced) return undefined

    const intervalId = window.setInterval(() => {
      setVisibleCount((current) => {
        const next = current >= steps.length ? 2 : current + 1

        if (current >= steps.length) {
          setCycle((value) => value + 1)
        }

        return next
      })
    }, 1200)

    return () => window.clearInterval(intervalId)
  }, [reduced, steps.length])

  const visibleSteps = steps.slice(0, visibleCount)
  const activeStep = visibleSteps[visibleSteps.length - 1]
  const progress = Math.round((visibleCount / steps.length) * 100)

  return (
    <div className="terminal-panel terminal-run mt-8 w-full max-w-[860px] px-4 py-4 text-left">
      <div className="flex flex-col gap-4 border-b border-white/8 pb-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="terminal-label text-[10px] font-semibold">live session</div>
          <div className="mt-2 flex items-center gap-3 text-[12px] text-[#9ab5df]">
            <span className="terminal-live-dot" />
            <span className="terminal-mono uppercase tracking-[0.16em] text-[#d8e7ff]">scan executing</span>
            <span className="terminal-run-divider">/</span>
            <span className="text-[#78a9ff]">{activeStep.stage}</span>
            <span className="text-white/42">[{activeStep.status}]</span>
          </div>
        </div>
        <div className="terminal-run-meta">
          <div>
            <span className="terminal-run-meta-label">progress</span>
            <span className="terminal-run-meta-value">{progress}%</span>
          </div>
          <div>
            <span className="terminal-run-meta-label">cycle</span>
            <span className="terminal-run-meta-value">0{cycle + 1}</span>
          </div>
          <div>
            <span className="terminal-run-meta-label">active</span>
            <span className="terminal-run-meta-value">{activeStep.stage}</span>
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[220px,1fr]">
        <div className="terminal-soft px-4 py-4">
          <div className="terminal-label text-[10px] font-semibold">run state</div>
          <div className="mt-4 space-y-3">
            {steps.map((step, index) => {
              const state = index < visibleCount - 1 ? 'done' : index === visibleCount - 1 ? 'active' : 'pending'

              return (
                <div key={step.stage} className={`terminal-stage terminal-stage-${state}`}>
                  <div className="terminal-stage-index">{String(index + 1).padStart(2, '0')}</div>
                  <div>
                    <div className="terminal-stage-name">{step.stage}</div>
                    <div className="terminal-stage-status">{step.status}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="terminal-stream-panel">
          <div className="space-y-2 text-[12px] leading-[1.6] text-[#9ab5df]">
            {visibleSteps.map((step, index) => (
              <div
                key={`${step.stage}-${index}`}
                className={`terminal-mono terminal-stream-line ${
                  index === visibleSteps.length - 1 && !reduced ? 'terminal-stream-line-active' : ''
                }`}
              >
                <span className="terminal-stream-prefix">&gt;</span>
                <span>{step.line}</span>
                {index === visibleSteps.length - 1 && !reduced ? <span className="terminal-cursor" /> : null}
              </div>
            ))}
          </div>
          <div className="terminal-progress mt-5">
            <div className="terminal-progress-bar" style={{ width: `${progress}%` }} />
          </div>
        </div>
      </div>
    </div>
  )
}

function WorkflowVisual({ type }) {
  if (type === 'steps') {
    const rows = [
      ['Collecting prompts', 'GitHub / Postman / App logs'],
      ['Pulling context', 'Repo diff / policy / metadata'],
      ['Analyzing with agent', 'Static + Claude semantic audit'],
      ['Building findings', 'CWE / OWASP / evidence'],
      ['Syncing deliverables', 'Checks / reports / audit trail'],
    ]

    return (
      <div className="flex h-full flex-col justify-center px-5 py-6 text-white/38">
        {rows.map(([label, sub]) => (
          <div key={label} className="mb-3 flex items-start gap-2.5 last:mb-0">
            <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-white/28" />
            <div>
              <div className="text-[13px] font-medium tracking-[-0.02em] text-white/34">{label}</div>
              <div className="mt-0.5 text-[11px] text-white/20">{sub}</div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (type === 'table') {
    const rows = [
      ['1', 'DIRECT_INJECTION', 'Critical', 'orange'],
      ['2', 'SECRET_IN_PROMPT', 'High', 'gray'],
      ['3', 'ROLE_CONFUSION', 'Medium', 'orange'],
      ['4', 'DATA_LEAKAGE', 'High', 'gray'],
    ]

    return (
      <div className="grid h-full place-items-center px-5 py-6">
        <div className="w-full max-w-[440px] overflow-hidden border border-white/6 text-white/52">
          {rows.map(([index, value, tag, tone]) => (
            <div key={`${index}-${value}`} className="grid grid-cols-[48px,1fr,100px] border-b border-white/6 last:border-b-0">
              <div className="border-r border-white/6 px-3 py-2.5 text-[13px]">{index}</div>
              <div className="border-r border-white/6 px-3 py-2.5 font-mono text-[12px]">{value}</div>
              <div className="px-3 py-2">
                <span
                  className={`inline-flex border px-2 py-1 text-[11px] font-medium ${
                    tone === 'orange'
                      ? 'border-[#ff7f50]/40 bg-[#ff7f50] text-white'
                      : 'border-white/6 bg-white/16 text-white/76'
                  }`}
                >
                  {tag}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (type === 'clauses') {
    return (
      <div className="relative h-full overflow-hidden px-6 py-6">
        <div className="relative flex h-full flex-col justify-center gap-5">
          {[
            ['01', 'Indirect prompt injection'],
            ['02', 'PII leakage risk'],
            ['03', 'Unverified tool action'],
          ].map(([index, label], rowIndex) => (
            <div
              key={index}
              className={`flex items-center gap-2.5 ${rowIndex === 1 ? 'ml-8' : rowIndex === 2 ? 'ml-16' : ''}`}
            >
              <span className="rounded-[3px] bg-white px-1.5 py-0.5 text-[11px] font-semibold text-[#2b2825]">
                {index}
              </span>
              <span className="rounded-[3px] border border-white/70 px-3 py-1.5 text-[13px] font-medium text-white/90">
                {label}
              </span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex h-full items-center justify-center overflow-hidden px-6 py-6">
      <div className="relative flex w-full max-w-[360px] flex-col gap-4 text-white/92">
        {[
          { label: 'PromptShield Evidence Pack.pdf', tone: 'bg-[#ff7642]' },
          { label: 'OWASP LLM Compliance.csv', tone: 'bg-[#43b26d]' },
          { label: '.promptshield.yml Policy.pdf', tone: 'bg-[#5f95ff]' },
        ].map((file) => (
          <div
            key={file.label}
            className="glass-file flex items-center justify-between gap-3 border border-white/75 bg-white/10 px-4 py-2.5 text-[13px]"
          >
            <div className="flex min-w-0 items-center gap-4">
              <span className={`h-3 w-3 ${file.tone}`} />
              <span className="truncate">{file.label}</span>
            </div>
            <Download className="h-4 w-4 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  )
}

function WorkflowCard({ card, reduced, delay }) {
  return (
    <Reveal reduced={reduced} delay={delay} className="h-full">
      <article className="workflow-card flex h-full flex-col border border-white/8 bg-[#0d1c31] text-white">
        <div className="workflow-visual min-h-[180px] border-b border-white/8">
          <WorkflowVisual type={card.visual} />
        </div>
        <div className="flex flex-1 flex-col px-4 pb-4 pt-4">
          <GlassChip>{card.badge}</GlassChip>
          <h3 className="mt-4 max-w-[22ch] text-[16px] font-medium leading-[1.2] tracking-[-0.03em] text-white">
            {card.title}
          </h3>
          <p className="mt-2 max-w-[30ch] text-[12px] leading-[1.5] tracking-[-0.01em] text-white/50">
            {card.description}
          </p>
        </div>
      </article>
    </Reveal>
  )
}

function MetricCard({ item, reduced, delay }) {
  return (
    <Reveal reduced={reduced} delay={delay} className="h-full">
      <div className="grid h-full gap-3">
        <article className="liquid-panel flex min-h-[200px] flex-col overflow-hidden px-5 py-5 text-white">
          <div className="terminal-label text-[9px] font-semibold">{item.badge}</div>
          <div className="font-display text-[clamp(2.5rem,4vw,3.5rem)] leading-[0.9] tracking-[-0.05em]">
            {item.stat}
          </div>
          <div className="mt-2 max-w-[18ch] text-[13px] font-medium leading-[1.35] tracking-[-0.02em] text-white/85">
            {item.label}
          </div>
          <div className="mt-auto pt-4 text-[10px] uppercase tracking-[0.18em] text-[#78a9ff]">
            prompt review telemetry
          </div>
        </article>
        <article className="metric-shift-card px-4 py-4 text-white">
          <div className="flex items-center justify-between gap-4">
            <div className="terminal-label text-[9px] font-semibold">baseline shift</div>
            <span className="metric-badge">
              {item.badge}
            </span>
          </div>

          <div className="mt-5 grid gap-3">
            <div className="metric-state-card">
              <div className="metric-state-heading">
                <span>Before</span>
                <span className="metric-state-slash">/</span>
                <span>legacy workflow</span>
              </div>
              <div className="metric-state-value text-white/80 text-sm">{item.before}</div>
              <div className="metric-state-note text-[12px]">{item.beforeNote}</div>
            </div>

            <div className="metric-shift-arrow">
              <span className="metric-shift-line" />
              <span className="metric-shift-marker">-&gt;</span>
              <span className="metric-shift-line" />
            </div>

            <div className="metric-state-card metric-state-card-active">
              <div className="metric-state-heading">
                <span>With PromptShield</span>
                <span className="metric-state-slash">/</span>
                <span>current workflow</span>
              </div>
              <div className="metric-state-value text-white text-sm">{item.after}</div>
              <div className="metric-state-note text-[#b8d1f7] text-[12px]">{item.afterNote}</div>
            </div>
          </div>
        </article>
      </div>
    </Reveal>
  )
}

function TestimonialCard({ testimonial, reduced, delay }) {
  return (
    <Reveal reduced={reduced} delay={delay} className="h-full">
      <article className="app-panel h-full px-5 py-4 text-[#eff6ff]">
        <div className="text-[9px] uppercase tracking-[0.12em] text-[#8fb2e5]">{testimonial.label}</div>
        <div className="mt-1 text-[14px] font-semibold tracking-[-0.03em]">{testimonial.metric}</div>
        <p className="mt-3 max-w-[50ch] text-[13px] leading-[1.5] tracking-[-0.02em] text-[#c7d8f2]">
          <span className="mr-1 text-[#7db2ff]">"</span>
          {testimonial.quote}
          <span className="ml-1 text-[#7db2ff]">"</span>
        </p>
        <div className="mt-4 flex items-center gap-2 text-[11px] text-[#90acd6]">
          <span className="grid h-6 w-6 place-items-center rounded-full bg-[#12243d] text-[9px] font-semibold text-[#f3f7ff]">
            {testimonial.name
              .split(' ')
              .map((part) => part[0])
              .slice(0, 2)
              .join('')}
          </span>
          <div>
            <div className="font-semibold text-[#f3f7ff] text-[11px]">{testimonial.name}</div>
            <div className="text-[10px]">{testimonial.title}</div>
          </div>
        </div>
      </article>
    </Reveal>
  )
}

export default function LandingPage({ onEnterDashboard, onEnterScan, onToneChange }) {
  const reduced = useReducedMotion()

  useEffect(() => {
    if (!onToneChange) return undefined

    const sections = [
      { id: 'hero', tone: 'blue' },
      { id: 'workflows', tone: 'gray' },
      { id: 'proof', tone: 'white' },
      { id: 'security', tone: 'white' },
    ]

    onToneChange('blue')

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
        if (!visible?.target?.id) return
        const match = sections.find((section) => section.id === visible.target.id)
        if (match) onToneChange(match.tone)
      },
      {
        root: null,
        rootMargin: '-35% 0px -45% 0px',
        threshold: [0.1, 0.25, 0.5, 0.75],
      }
    )

    for (const section of sections) {
      const node = document.getElementById(section.id)
      if (node) observer.observe(node)
    }

    return () => observer.disconnect()
  }, [onToneChange])

  return (
    <div className="landing-shell font-body text-white">
      <section className="liquid-surface border-b border-white/10">
        <div className="mx-auto flex min-h-screen max-w-[1700px] flex-col px-6 pb-10 pt-10 sm:px-10 sm:pt-12 lg:px-12 lg:pt-14">
          <div id="hero" className="flex flex-1 items-center justify-center py-20 sm:py-24 lg:py-16">
            <Reveal reduced={reduced} className="flex w-full max-w-[1040px] flex-col items-center">
              <h1 className="terminal-mono mx-auto max-w-[18ch] text-center text-[clamp(2rem,4.7vw,4.4rem)] font-semibold uppercase leading-[1.08] tracking-[-0.03em] text-[#eef5ff]">
                Prompt security
                <br />
                before risky AI
                <br />
                changes merge.
              </h1>
              <p className="font-condensed mt-4 text-[12px] uppercase tracking-[0.28em] text-[#78a9ff]">
                Catch prompt risk before it lands.
              </p>
              <p className="mx-auto mt-6 max-w-[620px] text-center text-[clamp(0.9rem,1.25vw,1.02rem)] leading-[1.45] tracking-[-0.01em] text-[#9ab5df]">
                Scans pull-request prompts and code, runs static and Claude semantic checks in parallel, and gates merges against CWE and OWASP LLM risks.
              </p>
              <div className="mt-12 flex flex-wrap items-center justify-center gap-4">
                <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
                <LiquidButton onClick={() => scrollToSection('workflows', reduced)} tone="dark" icon>
                  See workflows
                </LiquidButton>
              </div>
              <TerminalLogBlock reduced={reduced} />
            </Reveal>
          </div>

          <HeroTrustRow reduced={reduced} />
        </div>
      </section>

      <section id="workflows" className="landing-phase-gray px-6 py-16 sm:px-10 lg:px-12 lg:py-20">
        <div className="mx-auto max-w-[1800px]">
          <Reveal reduced={reduced}>
            <h2 className="terminal-mono max-w-[1080px] text-[clamp(1.4rem,2.4vw,2.2rem)] font-semibold uppercase leading-[1.2] tracking-[-0.02em] text-white">
              What PromptShield already does in this repo.
            </h2>
          </Reveal>
          <div className="mt-12 grid gap-4 xl:grid-cols-4">
            {WORKFLOW_CARDS.map((card, index) => (
              <WorkflowCard key={card.id} card={card} reduced={reduced} delay={index * 0.08} />
            ))}
          </div>
        </div>
      </section>

      <section className="landing-phase-white-soft px-6 pb-4 sm:px-10 lg:px-12 lg:pb-6">
        <div className="mx-auto max-w-[1800px]">
          <div className="grid gap-4 xl:grid-cols-3">
            {METRICS.map((item, index) => (
              <MetricCard key={item.stat} item={item} reduced={reduced} delay={index * 0.08} />
            ))}
          </div>
        </div>
      </section>

      <section id="proof" className="landing-phase-white px-4 py-6 sm:px-8 lg:px-12 lg:py-8">
        <div className="mx-auto max-w-[1700px] overflow-hidden text-[#e9f3ff]">
          <div className="grid gap-4 border-b border-white/10 pb-4 lg:grid-cols-2">
            {TESTIMONIALS.map((testimonial, index) => (
              <TestimonialCard
                key={testimonial.name}
                testimonial={testimonial}
                reduced={reduced}
                delay={index * 0.08}
              />
            ))}
          </div>

          <Reveal reduced={reduced} className="app-panel mt-3 overflow-x-auto border-b border-transparent">
            <div className="min-w-[920px] px-4 py-3 sm:px-6">
              <div className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 px-4 py-2 text-[10px] uppercase tracking-[0.12em] text-[#84a2cc]">
                <div />
                <div>Before</div>
                <div>With PromptShield</div>
                <div>Result</div>
              </div>
              {RESULTS.map((row) => (
                <div
                  key={row.workflow}
                  className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 border-t border-white/8 px-4 py-3"
                >
                  <div>
                    <div className="text-[14px] font-medium tracking-[-0.02em] text-[#f4f8ff]">
                      {row.workflow}
                    </div>
                  </div>
                  <div className="text-[12px] leading-[1.35] text-[#88a2ca]">
                    <div className="text-[10px] uppercase tracking-[0.1em]">{row.beforeLabel}</div>
                    <div className="mt-1 text-[#c8d8f0]">{row.before}</div>
                  </div>
                  <div className="text-[12px] leading-[1.35] text-[#88a2ca]">
                    <div className="text-[10px] uppercase tracking-[0.1em]">{row.afterLabel}</div>
                    <div className="mt-1 font-medium text-[#eff6ff]">{row.after}</div>
                  </div>
                  <div className="text-[12px] leading-[1.35] text-[#6cabff]">{row.result}</div>
                </div>
              ))}
            </div>
          </Reveal>

          <div className="mt-3 grid gap-4 border-b border-white/10 pb-4 lg:grid-cols-3">
            {OUTCOMES.map((outcome, index) => (
              <Reveal key={outcome.title} reduced={reduced} delay={index * 0.08} className="h-full">
                <article className="app-panel flex h-full flex-col px-4 py-4">
                  <h3 className="max-w-[24ch] text-[14px] leading-[1.3] tracking-[-0.02em] text-[#f5f8ff]">
                    {outcome.title}
                  </h3>
                  <div className="mt-6 text-[24px] font-medium tracking-[-0.04em] text-[#6cabff]">
                    {outcome.stat}
                  </div>
                  <div className="mt-1 text-[11px] text-[#8eaad2]">{outcome.detail}</div>
                </article>
              </Reveal>
            ))}
          </div>

          <div id="security" className="grid gap-8 px-6 py-7 sm:px-8 lg:grid-cols-[1.3fr,1fr] lg:gap-12">
            <Reveal reduced={reduced}>
              <div className="flex items-center gap-2.5 text-[18px] font-medium tracking-[-0.03em] text-[#eff6ff]">
                <ShieldCheck className="h-5 w-5 text-[#eff6ff]" />
                <span>Enterprise-grade security</span>
              </div>
              <p className="mt-3 max-w-[64ch] text-[15px] leading-[1.6] text-[#93add4]">
                Your data stays yours. PromptShield keeps review artifacts isolated, preserves auditability, and never trains on your private releases.
              </p>
              <button className="mt-4 inline-flex items-center gap-2 text-[12px] font-semibold tracking-[-0.02em] text-[#d6e5ff]">
                <span>Security &amp; Trust Center</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </Reveal>

            <Reveal reduced={reduced} delay={0.08}>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                {SECURITY_BADGES.map((badge) => (
                  <div
                    key={badge}
                    className="app-panel-soft grid min-h-[56px] place-items-center px-3 text-center text-[11px] font-semibold tracking-[0.04em] text-[#e7f2ff]"
                  >
                    {badge}
                  </div>
                ))}
              </div>
            </Reveal>
          </div>

          <Reveal reduced={reduced} className="border-t border-white/10 px-5 py-3 sm:px-8">
            <div className="grid gap-3 text-[11px] text-[#93add4] sm:grid-cols-2 xl:grid-cols-6">
              {[
                'Audited & tested',
                'Fine-grained access controls',
                'Modern secure practices',
                'Audit logs across every workflow',
                'No training on your data',
                'Regional deployment options',
              ].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#7eb5ff]" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      <section className="liquid-surface border-t border-white/10">
        <div className="mx-auto max-w-[1700px] px-6 py-10 sm:px-10 lg:px-12 lg:py-12">
          <Reveal reduced={reduced}>
            <div className="inline-flex items-center gap-2 text-[10px] font-medium tracking-[0.08em] text-white/74">
              <Sparkles className="h-3.5 w-3.5" strokeWidth={2.1} />
              <span>Precision AI for institutional workflows</span>
            </div>
            <h2 className="mt-6 max-w-[620px] text-[clamp(2.2rem,4vw,3.6rem)] font-medium leading-[0.96] tracking-[-0.05em] text-white">
              Build once.
              <br />
              Review across the team.
              <br />
              Improve over time.
            </h2>
            <div className="mt-8">
              <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
            </div>
          </Reveal>
        </div>
      </section>

      <footer className="bg-[#000000] px-6 py-10 text-white/78 sm:px-10 lg:px-12 lg:py-12">
        <div className="mx-auto grid max-w-[1700px] gap-10 lg:grid-cols-[1.15fr_repeat(4,0.8fr)]">
          <div>
            <div className="text-[16px] font-semibold tracking-[0.08em] text-white">PS</div>
            <div className="mt-4 max-w-[14ch] text-[clamp(1.3rem,2vw,1.8rem)] leading-[1.1] tracking-[-0.04em] text-white">
              Prompt security purpose-built for AI code review.
            </div>
            <div className="mt-5">
              <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
            </div>
          </div>

          {FOOTER_COLUMNS.map((column) => (
            <div key={column.heading}>
              <h3 className="text-[12px] font-semibold tracking-[0.02em] text-white">{column.heading}</h3>
              <div className="mt-3 space-y-2 text-[12px] text-white/48">
                {column.links.map((link) => (
                  <div key={link}>{link}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </footer>
    </div>
  )
}
