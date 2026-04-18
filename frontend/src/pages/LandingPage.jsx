import { motion, useReducedMotion } from 'framer-motion'
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
  },
  {
    stat: '14',
    label: 'Structural jailbreak payloads used to pressure test flagged prompts',
    badge: 'Jailbreak engine',
    before: 'Ad hoc tests',
    after: 'Repeatable coverage',
  },
  {
    stat: '96%',
    label: 'F1 on the built-in 100-sample benchmark for vulnerable vs safe inputs',
    badge: 'Evaluation benchmark',
    before: 'Guesswork',
    after: 'Measured quality',
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
      className={`glass-chip inline-flex items-center gap-2 border border-white/10 bg-white/6 px-4 py-2 text-[13px] font-medium text-white/62 ${className}`}
    >
      <Clock3 className="h-3.5 w-3.5" />
      <span>{children}</span>
    </div>
  )
}

function HeroTrustRow({ reduced }) {
  return (
    <Reveal reduced={reduced} delay={0.24}>
      <div className="mt-16 grid gap-8 border-t border-white/10 pt-8 text-white/96 sm:grid-cols-3 xl:grid-cols-6">
        {TRUST_MARKS.map((mark) => (
          <div
            key={mark}
            className="text-center text-[18px] font-semibold tracking-[0.04em] text-white/90 sm:text-left"
          >
            {mark}
          </div>
        ))}
      </div>
    </Reveal>
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
      <div className="flex h-full flex-col justify-center px-8 py-10 text-white/38">
        {rows.map(([label, sub]) => (
          <div key={label} className="mb-4 flex items-start gap-3 last:mb-0">
            <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-white/28" />
            <div>
              <div className="text-[18px] font-medium tracking-[-0.03em] text-white/34">{label}</div>
              <div className="mt-0.5 text-[14px] text-white/20">{sub}</div>
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
      <div className="grid h-full place-items-center px-8 py-10">
        <div className="w-full max-w-[520px] overflow-hidden border border-white/6 text-white/52">
          {rows.map(([index, value, tag, tone]) => (
            <div key={`${index}-${value}`} className="grid grid-cols-[80px,1fr,160px] border-b border-white/6 last:border-b-0">
              <div className="border-r border-white/6 px-6 py-4 text-[22px]">{index}</div>
              <div className="border-r border-white/6 px-6 py-4 font-mono text-[18px]">{value}</div>
              <div className="px-6 py-3">
                <span
                  className={`inline-flex border px-3 py-1.5 text-[14px] font-medium ${
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
      <div className="relative h-full overflow-hidden px-10 py-10">
        <div className="relative flex h-full flex-col justify-center gap-8">
          {[
            ['01', 'Indirect prompt injection'],
            ['02', 'PII leakage risk'],
            ['03', 'Unverified tool action'],
          ].map(([index, label], rowIndex) => (
            <div
              key={index}
              className={`flex items-center gap-3 ${rowIndex === 1 ? 'ml-12' : rowIndex === 2 ? 'ml-24' : ''}`}
            >
              <span className="rounded-[4px] bg-white px-2 py-1 text-[14px] font-semibold text-[#2b2825]">
                {index}
              </span>
              <span className="rounded-[4px] border border-white/70 px-4 py-2 text-[18px] font-medium text-white/90">
                {label}
              </span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex h-full items-center justify-center overflow-hidden px-10 py-10">
      <div className="relative flex w-full max-w-[420px] flex-col gap-8 text-white/92">
        {[
          { label: 'PromptShield Evidence Pack.pdf', tone: 'bg-[#ff7642]' },
          { label: 'OWASP LLM Compliance.csv', tone: 'bg-[#43b26d]' },
          { label: '.promptshield.yml Policy.pdf', tone: 'bg-[#5f95ff]' },
        ].map((file) => (
          <div
            key={file.label}
            className="glass-file flex items-center justify-between gap-4 border border-white/75 bg-white/10 px-5 py-3 text-[18px]"
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
        <div className="workflow-visual min-h-[360px] border-b border-white/8">
          <WorkflowVisual type={card.visual} />
        </div>
        <div className="flex flex-1 flex-col px-8 pb-10 pt-7">
          <GlassChip>{card.badge}</GlassChip>
          <h3 className="mt-8 max-w-[20ch] text-[28px] font-medium leading-[1.12] tracking-[-0.04em] text-white">
            {card.title}
          </h3>
          <p className="mt-5 max-w-[26ch] text-[18px] leading-[1.45] tracking-[-0.02em] text-white/44">
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
      <div className="grid h-full gap-4">
        <article className="liquid-panel flex min-h-[390px] flex-col overflow-hidden px-10 py-10 text-white">
          <div className="font-display text-[clamp(5rem,8vw,8rem)] leading-[0.88] tracking-[-0.06em]">
            {item.stat}
          </div>
          <div className="mt-auto max-w-[15ch] text-[20px] font-medium leading-[1.28] tracking-[-0.03em] text-white/90">
            {item.label}
          </div>
        </article>
        <article className="border border-white/8 bg-[#0b1527] px-8 py-8 text-white">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-4 text-[18px] tracking-[-0.03em]">
              <span className="font-medium text-white/94">Before</span>
              <span className="text-white/34">with PromptShield</span>
            </div>
            <span className="glass-chip border border-white/10 bg-white/5 px-4 py-2 text-[14px] text-white/46">
              {item.badge}
            </span>
          </div>
          <div className="mt-12 font-display text-[clamp(3.5rem,4vw,4.75rem)] leading-[0.95] tracking-[-0.05em] text-white/96">
            {item.before}
          </div>
          <div className="mt-6 font-display text-[clamp(3rem,3.8vw,4.5rem)] leading-[0.95] tracking-[-0.05em] text-white/26">
            {item.after}
          </div>
        </article>
      </div>
    </Reveal>
  )
}

function TestimonialCard({ testimonial, reduced, delay }) {
  return (
    <Reveal reduced={reduced} delay={delay} className="h-full">
      <article className="app-panel h-full px-8 py-7 text-[#eff6ff]">
        <div className="text-[11px] uppercase tracking-[0.12em] text-[#8fb2e5]">{testimonial.label}</div>
        <div className="mt-1 text-[22px] font-semibold tracking-[-0.03em]">{testimonial.metric}</div>
        <p className="mt-6 max-w-[46ch] text-[21px] leading-[1.48] tracking-[-0.03em] text-[#c7d8f2]">
          <span className="mr-1 text-[#7db2ff]">"</span>
          {testimonial.quote}
          <span className="ml-1 text-[#7db2ff]">"</span>
        </p>
        <div className="mt-9 flex items-center gap-3 text-[13px] text-[#90acd6]">
          <span className="grid h-8 w-8 place-items-center rounded-full bg-[#12243d] text-[11px] font-semibold text-[#f3f7ff]">
            {testimonial.name
              .split(' ')
              .map((part) => part[0])
              .slice(0, 2)
              .join('')}
          </span>
          <div>
            <div className="font-semibold text-[#f3f7ff]">{testimonial.name}</div>
            <div>{testimonial.title}</div>
          </div>
        </div>
      </article>
    </Reveal>
  )
}

export default function LandingPage({ onEnterDashboard, onEnterScan }) {
  const reduced = useReducedMotion()

  return (
    <div className="landing-shell font-body text-white">
      <section className="liquid-surface border-b border-white/10">
        <div className="mx-auto flex min-h-screen max-w-[1700px] flex-col px-6 pb-10 pt-6 sm:px-10 lg:px-12">
          <div className="landing-ibm-header flex items-center justify-between gap-4 px-4 py-3">
            <button
              onClick={() => scrollToSection('hero', reduced)}
              className="landing-ibm-logo px-4 py-2 text-[13px] font-semibold tracking-[0.08em] text-white/90 transition-colors"
            >
              PromptShield
            </button>
            <div className="hidden items-center gap-2 lg:flex">
              <button
                onClick={() => scrollToSection('workflows', reduced)}
                className="landing-ibm-nav px-4 py-2 text-[13px] text-white/75 transition-colors hover:text-white"
              >
                Platform
              </button>
              <button
                onClick={() => scrollToSection('proof', reduced)}
                className="landing-ibm-nav px-4 py-2 text-[13px] text-white/75 transition-colors hover:text-white"
              >
                Outcomes
              </button>
              <button
                onClick={() => scrollToSection('security', reduced)}
                className="landing-ibm-nav px-4 py-2 text-[13px] text-white/75 transition-colors hover:text-white"
              >
                Security
              </button>
              <LiquidButton onClick={onEnterScan} tone="dark">
                Run a live scan
              </LiquidButton>
              <LiquidButton onClick={onEnterDashboard} icon>
                Access dashboard
              </LiquidButton>
            </div>
          </div>

          <div id="hero" className="flex flex-1 items-center justify-center py-20 sm:py-24 lg:py-16">
            <Reveal reduced={reduced} className="flex w-full max-w-[1040px] flex-col items-center">
              <div className="mb-8 inline-flex items-center gap-2 text-[12px] font-medium tracking-[0.08em] text-white/76">
                <Sparkles className="h-4 w-4" strokeWidth={2} />
                <span>Institutional AI orchestration</span>
              </div>
              <h1 className="mx-auto max-w-[12ch] text-center font-display text-[clamp(4.1rem,7.4vw,8.6rem)] leading-[0.92] tracking-[-0.065em]">
                <span className="block text-white/52">Prompt security</span>
                <span className="block text-white">before risky AI changes merge.</span>
              </h1>
              <p className="mx-auto mt-10 max-w-[900px] text-center text-[clamp(1.25rem,2.1vw,1.9rem)] leading-[1.35] tracking-[-0.04em] text-white/82">
                PromptShield scans prompts and code in pull requests, runs static plus Claude-powered semantic analysis in parallel, maps findings to CWE and the OWASP LLM Top 10, and turns review into a policy gate instead of a last-minute scramble.
              </p>
              <div className="mt-12 flex flex-wrap items-center justify-center gap-4">
                <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
                <LiquidButton onClick={() => scrollToSection('workflows', reduced)} tone="dark" icon>
                  See workflows
                </LiquidButton>
              </div>
            </Reveal>
          </div>

          <HeroTrustRow reduced={reduced} />
        </div>
      </section>

      <section id="workflows" className="bg-[#07111d] px-6 py-16 sm:px-10 lg:px-12 lg:py-20">
        <div className="mx-auto max-w-[1800px]">
          <Reveal reduced={reduced}>
            <h2 className="max-w-[1080px] text-[clamp(2.75rem,5vw,4.3rem)] font-medium leading-[1.02] tracking-[-0.06em] text-white">
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

      <section className="bg-[#07111d] px-6 pb-6 sm:px-10 lg:px-12 lg:pb-10">
        <div className="mx-auto max-w-[1800px]">
          <div className="grid gap-4 xl:grid-cols-3">
            {METRICS.map((item, index) => (
              <MetricCard key={item.stat} item={item} reduced={reduced} delay={index * 0.08} />
            ))}
          </div>
        </div>
      </section>

      <section id="proof" className="bg-[#07111d] px-4 py-8 sm:px-8 lg:px-12 lg:py-10">
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

          <Reveal reduced={reduced} className="app-panel mt-4 overflow-x-auto border-b border-transparent">
            <div className="min-w-[920px] px-4 py-4 sm:px-6">
              <div className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 px-4 py-3 text-[11px] uppercase tracking-[0.12em] text-[#84a2cc]">
                <div />
                <div>Before</div>
                <div>With PromptShield</div>
                <div>Result</div>
              </div>
              {RESULTS.map((row) => (
                <div
                  key={row.workflow}
                  className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 border-t border-white/8 px-4 py-4"
                >
                  <div>
                    <div className="text-[15px] font-medium tracking-[-0.02em] text-[#f4f8ff]">
                      {row.workflow}
                    </div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#88a2ca]">
                    <div className="text-[11px] uppercase tracking-[0.1em]">{row.beforeLabel}</div>
                    <div className="mt-1 text-[#c8d8f0]">{row.before}</div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#88a2ca]">
                    <div className="text-[11px] uppercase tracking-[0.1em]">{row.afterLabel}</div>
                    <div className="mt-1 font-medium text-[#eff6ff]">{row.after}</div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#6cabff]">{row.result}</div>
                </div>
              ))}
            </div>
          </Reveal>

          <div className="mt-4 grid gap-4 border-b border-white/10 pb-4 lg:grid-cols-3">
            {OUTCOMES.map((outcome, index) => (
              <Reveal key={outcome.title} reduced={reduced} delay={index * 0.08} className="h-full">
                <article className="app-panel flex h-full flex-col px-6 py-6 lg:px-7">
                  <h3 className="max-w-[22ch] text-[21px] leading-[1.2] tracking-[-0.03em] text-[#f5f8ff]">
                    {outcome.title}
                  </h3>
                  <div className="mt-16 text-[42px] font-medium tracking-[-0.05em] text-[#6cabff]">
                    {outcome.stat}
                  </div>
                  <div className="mt-1 text-[13px] text-[#8eaad2]">{outcome.detail}</div>
                </article>
              </Reveal>
            ))}
          </div>

          <div id="security" className="grid gap-8 px-6 py-7 sm:px-8 lg:grid-cols-[1.3fr,1fr] lg:gap-12">
            <Reveal reduced={reduced}>
              <div className="flex items-center gap-3 text-[24px] font-medium tracking-[-0.04em] text-[#eff6ff]">
                <ShieldCheck className="h-5 w-5 text-[#eff6ff]" />
                <span>Enterprise-grade security</span>
              </div>
              <p className="mt-3 max-w-[64ch] text-[15px] leading-[1.6] text-[#93add4]">
                Your data stays yours. PromptShield keeps review artifacts isolated, preserves auditability, and never trains on your private releases.
              </p>
              <button className="mt-5 inline-flex items-center gap-2 text-[13px] font-semibold tracking-[-0.02em] text-[#d6e5ff]">
                <span>Security &amp; Trust Center</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </Reveal>

            <Reveal reduced={reduced} delay={0.08}>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                {SECURITY_BADGES.map((badge) => (
                  <div
                    key={badge}
                    className="app-panel-soft grid min-h-[92px] place-items-center px-3 text-center text-[14px] font-semibold tracking-[0.04em] text-[#e7f2ff]"
                  >
                    {badge}
                  </div>
                ))}
              </div>
            </Reveal>
          </div>

          <Reveal reduced={reduced} className="border-t border-white/10 px-5 py-4 sm:px-8">
            <div className="grid gap-3 text-[12px] text-[#93add4] sm:grid-cols-2 xl:grid-cols-6">
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
        <div className="mx-auto max-w-[1700px] px-6 py-20 sm:px-10 lg:px-12 lg:py-24">
          <Reveal reduced={reduced}>
            <div className="inline-flex items-center gap-2 text-[12px] font-medium tracking-[0.08em] text-white/78">
              <Sparkles className="h-3.5 w-3.5" strokeWidth={2.1} />
              <span>Precision AI for institutional workflows</span>
            </div>
            <h2 className="mt-8 max-w-[720px] text-[clamp(3.4rem,6vw,6.4rem)] font-medium leading-[0.94] tracking-[-0.06em] text-white">
              Build once.
              <br />
              Review across the team.
              <br />
              Improve over time.
            </h2>
            <div className="mt-10">
              <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
            </div>
          </Reveal>
        </div>
      </section>

      <footer className="bg-[#08111d] px-6 py-12 text-white/78 sm:px-10 lg:px-12 lg:py-14">
        <div className="mx-auto grid max-w-[1700px] gap-12 lg:grid-cols-[1.15fr_repeat(4,0.8fr)]">
          <div>
            <div className="text-[22px] font-semibold tracking-[0.08em] text-white">PS</div>
            <div className="mt-8 max-w-[12ch] text-[clamp(2rem,3vw,3.2rem)] leading-[1.02] tracking-[-0.05em] text-white">
              Prompt security purpose-built for AI code review.
            </div>
            <div className="mt-8">
              <LiquidButton onClick={onEnterDashboard}>Access dashboard</LiquidButton>
            </div>
          </div>

          {FOOTER_COLUMNS.map((column) => (
            <div key={column.heading}>
              <h3 className="text-[13px] font-semibold tracking-[0.02em] text-white">{column.heading}</h3>
              <div className="mt-4 space-y-3 text-[13px] text-white/48">
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
