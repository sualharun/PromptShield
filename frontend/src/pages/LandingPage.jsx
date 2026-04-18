import { motion, useReducedMotion } from 'framer-motion'
import { ArrowRight, ChevronRight, Clock3, Download, ShieldCheck, Sparkles } from 'lucide-react'

const TRUST_MARKS = [
  'OpenAI',
  'Anthropic',
  'Azure OpenAI',
  'AWS',
  'Databricks',
  'Snowflake',
]

const WORKFLOW_CARDS = [
  {
    id: 'review',
    badge: 'Hours back, every week',
    title: 'Prompt review, fully automated',
    description:
      'From intake to release, run policy checks, adversarial simulations, and escalation logic end-to-end.',
    visual: 'steps',
  },
  {
    id: 'scoring',
    badge: 'Triage time down 68%',
    title: 'Scanning as a repeatable system',
    description:
      'Extract risky instructions, severity, and mitigation steps from prompts and model outputs in minutes.',
    visual: 'table',
  },
  {
    id: 'redteam',
    badge: '24x faster. 57% more coverage',
    title: 'Automated red-teaming your team can rely on',
    description:
      'Probe jailbreaks, leakage, and indirect injections with structured findings that stay source-linked.',
    visual: 'clauses',
  },
  {
    id: 'release',
    badge: '3 days to 40 minutes',
    title: 'Release outputs traceable to source',
    description:
      'Generate audit-ready reports, policy deltas, and evidence packs backed by every prompt and response.',
    visual: 'files',
  },
]

const METRICS = [
  {
    stat: '9.4M',
    label: 'Prompts evaluated across production and pre-release workflows',
    badge: 'Prompt review',
    before: '100+ Hours',
    after: 'under 10 Hours',
  },
  {
    stat: '72%',
    label: 'Reduction in manual approval effort for high-volume AI releases',
    badge: 'Release ops',
    before: '2-3 Days',
    after: '20 Minutes',
  },
  {
    stat: '4 min',
    label: 'Average time to assemble a complete evidence pack for leadership',
    badge: 'Audit prep',
    before: '5 review tools',
    after: '1 control plane',
  },
]

const TESTIMONIALS = [
  {
    label: 'Time saved in release review',
    metric: '95%',
    quote:
      'We wanted prompt security to move at product speed. PromptShield gave our team a way to review, red-team, and document every release without adding headcount.',
    name: 'James Tomlinson',
    title: 'Managing Director',
  },
  {
    label: 'Productivity increase',
    metric: '37%',
    quote:
      'PromptShield automated the diligence loop around our agent launches. We now ship with clearer ownership, faster approvals, and a cleaner audit trail.',
    name: 'Trey Heath',
    title: 'CEO of Centerline',
  },
]

const RESULTS = [
  {
    workflow: 'System prompt launch review',
    beforeLabel: 'Review time',
    before: 'Expensive',
    afterLabel: 'Review time',
    after: '1/10th',
    result: 'Deploy time 20x faster',
  },
  {
    workflow: 'Prompt injection testing',
    beforeLabel: 'Test entry',
    before: 'Manual',
    afterLabel: 'Test entry',
    after: 'Automated',
    result: 'Productivity gain 37% in first month',
  },
  {
    workflow: 'Policy exception handling',
    beforeLabel: 'Per request',
    before: '45-60 min',
    afterLabel: 'Per request',
    after: '<15 min',
    result: 'Cost per contact $1,000 to $100',
  },
  {
    workflow: 'Prospect research & qualification',
    beforeLabel: 'Per release',
    before: 'Manual',
    afterLabel: 'Per release',
    after: 'Automated',
    result: '95% less manual work',
  },
  {
    workflow: 'Evidence pack assembly',
    beforeLabel: 'Per approval',
    before: '~60 min',
    afterLabel: 'Per approval',
    after: '~6 min',
    result: '90% faster review time',
  },
  {
    workflow: 'Incident response package',
    beforeLabel: 'Daily throughput',
    before: '~45 cases',
    afterLabel: 'Daily throughput',
    after: '+60 cases',
    result: '33% capacity increase',
  },
]

const OUTCOMES = [
  {
    title: 'Credit platform cuts prompt triage from hours to minutes',
    stat: '200+',
    detail: 'high-risk prompts processed per year',
  },
  {
    title: 'Long/short AI team accelerates launch decisions with richer evidence',
    stat: '3x',
    detail: 'more source context in each investment decision',
  },
  {
    title: 'Global enterprise rolls out copilots without adding governance headcount',
    stat: '137%',
    detail: 'increase in releases screened annually',
  },
]

const SECURITY_BADGES = [
  'SOC 2',
  'GDPR',
  'Audit Logs',
  'RBAC',
  'Zero Training',
]

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
    heading: 'Industries',
    links: ['Finance', 'Healthcare', 'Insurance', 'SaaS', 'Public sector'],
  },
  {
    heading: 'Resources',
    links: ['Insights', 'News', 'Events', 'Customer stories', 'Documentation', 'Pricing'],
  },
  {
    heading: 'Company',
    links: ['About', 'Careers', 'Contact', 'Security', 'Trust Center'],
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
      initial={reduced ? { opacity: 1, y: 0 } : { opacity: 0, y: 28 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.18 }}
      transition={
        reduced
          ? { duration: 0 }
          : { duration: 0.7, delay, ease: [0.22, 1, 0.36, 1] }
      }
    >
      {children}
    </motion.div>
  )
}

function LiquidButton({ children, onClick, tone = 'light', icon = false }) {
  const toneClass =
    tone === 'dark'
      ? 'border-white/15 bg-black/20 text-white hover:bg-black/28'
      : 'border-white/70 bg-white/88 text-[#272523] hover:bg-white'

  return (
    <button
      onClick={onClick}
      className={`liquid-button inline-flex items-center gap-2 border px-5 py-3 text-sm font-semibold tracking-[-0.02em] shadow-[0_18px_60px_rgba(17,12,8,0.12)] transition-all duration-300 hover:-translate-y-0.5 ${toneClass}`}
    >
      <span>{children}</span>
      {icon && <ArrowRight className="h-4 w-4" strokeWidth={2.2} />}
    </button>
  )
}

function GlassChip({ children, className = '' }) {
  return (
    <div
      className={`glass-chip inline-flex items-center gap-2 border border-white/10 bg-white/6 px-4 py-2 text-[13px] font-medium text-white/62 shadow-[0_12px_30px_rgba(0,0,0,0.18)] backdrop-blur-xl ${className}`}
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
            className="text-center text-[22px] font-semibold tracking-[0.06em] text-white/90 sm:text-left"
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
      ['Pulling context', 'Docs / tickets / policies'],
      ['Analyzing with agent', 'Security + compliance'],
      ['Building findings', 'Severity, fixes, approvals'],
      ['Syncing deliverables', 'Jira / Slack / evidence pack'],
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
      ['1', '$374,372', 'Conflict', 'orange'],
      ['2', '$2,374,372', 'filename.pdf', 'gray'],
      ['3', '$374,372', 'Conflict', 'orange'],
      ['4', '$2,374,372', 'filename.pdf', 'gray'],
    ]

    return (
      <div className="grid h-full place-items-center px-8 py-10">
        <div className="w-full max-w-[520px] overflow-hidden border border-white/6 text-white/52">
          {rows.map(([index, value, tag, tone]) => (
            <div key={`${index}-${value}`} className="grid grid-cols-[80px,1fr,220px] border-b border-white/6 last:border-b-0">
              <div className="border-r border-white/6 px-6 py-4 text-[22px]">{index}</div>
              <div className="border-r border-white/6 px-6 py-4 text-[22px]">{value}</div>
              <div className="px-6 py-3">
                <span
                  className={`glass-chip inline-flex border px-3 py-1.5 text-[14px] font-medium ${
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
        <div className="absolute inset-x-12 top-10 h-20 rounded-full bg-white/5 blur-3xl" />
        <div className="absolute left-24 top-24 h-24 w-24 rounded-full bg-white/8 blur-2xl" />
        <div className="absolute right-20 top-20 h-24 w-28 rounded-full bg-white/10 blur-2xl" />
        <div className="absolute inset-x-20 bottom-16 h-28 rounded-full bg-white/7 blur-3xl" />
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
              <span className="rounded-[6px] bg-white px-2 py-1 text-[14px] font-semibold text-[#2b2825]">
                {index}
              </span>
              <span className="rounded-[6px] border border-white/70 px-4 py-2 text-[18px] font-medium text-white/90">
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
      <div className="absolute inset-12 rounded-full bg-white/12 blur-[90px]" />
      <div className="relative flex w-full max-w-[420px] flex-col gap-8 text-white/92">
        {[
          { label: 'PromptShield Evidence Pack.pdf', tone: 'bg-[#ff7642]' },
          { label: 'Release Findings.xlsx', tone: 'bg-[#43b26d]' },
          { label: 'Policy Delta Memo.pdf', tone: 'bg-[#ff6c6c]' },
        ].map((file) => (
          <div
            key={file.label}
            className="glass-file flex items-center justify-between gap-4 border border-white/75 bg-white/10 px-5 py-3 text-[18px] shadow-[0_12px_30px_rgba(0,0,0,0.18)] backdrop-blur-xl"
          >
            <div className="flex min-w-0 items-center gap-4">
              <span className={`h-3 w-3 rounded-full ${file.tone}`} />
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
      <article className="workflow-card flex h-full flex-col border border-white/8 bg-[#343331] text-white">
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
        <article className="border border-white/8 bg-[#333230] px-8 py-8 text-white">
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
      <article className="h-full border border-black/6 bg-[#fcfbf8] px-8 py-7 text-[#27231f]">
        <div className="text-[11px] uppercase tracking-[0.12em] text-[#8f877f]">{testimonial.label}</div>
        <div className="mt-1 text-[22px] font-semibold tracking-[-0.03em]">{testimonial.metric}</div>
        <p className="mt-6 max-w-[46ch] text-[21px] leading-[1.48] tracking-[-0.03em] text-[#3b352f]">
          <span className="mr-1 text-[#ff7f4c]">"</span>
          {testimonial.quote}
          <span className="ml-1 text-[#ff7f4c]">"</span>
        </p>
        <div className="mt-9 flex items-center gap-3 text-[13px] text-[#6b645d]">
          <span className="grid h-8 w-8 place-items-center rounded-full bg-[#efe8df] text-[11px] font-semibold text-[#302a25]">
            {testimonial.name
              .split(' ')
              .map((part) => part[0])
              .slice(0, 2)
              .join('')}
          </span>
          <div>
            <div className="font-semibold text-[#2c2621]">{testimonial.name}</div>
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
    <div className="landing-shell font-body bg-[#2f2d2b] text-white">
      <section className="liquid-surface border-b border-white/10">
        <div className="mx-auto flex min-h-screen max-w-[1700px] flex-col px-6 pb-10 pt-6 sm:px-10 lg:px-12">
          <div className="flex items-center justify-between gap-4">
            <button
              onClick={() => scrollToSection('hero', reduced)}
              className="nav-pill border border-white/18 bg-white/10 px-4 py-2 text-[13px] font-semibold tracking-[0.08em] text-white/90 shadow-[0_14px_32px_rgba(0,0,0,0.12)] backdrop-blur-xl"
            >
              PromptShield
            </button>
            <div className="hidden items-center gap-2 lg:flex">
              <button
                onClick={() => scrollToSection('workflows', reduced)}
                className="nav-pill border border-white/12 bg-black/10 px-4 py-2 text-[13px] text-white/75 backdrop-blur-xl transition-colors hover:bg-black/18 hover:text-white"
              >
                Platform
              </button>
              <button
                onClick={() => scrollToSection('proof', reduced)}
                className="nav-pill border border-white/12 bg-black/10 px-4 py-2 text-[13px] text-white/75 backdrop-blur-xl transition-colors hover:bg-black/18 hover:text-white"
              >
                Outcomes
              </button>
              <button
                onClick={() => scrollToSection('security', reduced)}
                className="nav-pill border border-white/12 bg-black/10 px-4 py-2 text-[13px] text-white/75 backdrop-blur-xl transition-colors hover:bg-black/18 hover:text-white"
              >
                Security
              </button>
              <LiquidButton onClick={onEnterScan} tone="dark">
                Run a live scan
              </LiquidButton>
              <LiquidButton onClick={onEnterDashboard} icon>
                Book a demo
              </LiquidButton>
            </div>
          </div>

          <div
            id="hero"
            className="flex flex-1 items-center py-20 sm:py-24 lg:justify-end lg:py-16"
          >
            <Reveal reduced={reduced} className="w-full max-w-[980px] lg:mr-[3vw]">
              <div className="mb-8 inline-flex items-center gap-2 text-[12px] font-medium tracking-[0.08em] text-white/76">
                <Sparkles className="h-4 w-4" strokeWidth={2} />
                <span>Institutional AI orchestration</span>
              </div>
              <h1 className="font-display text-[clamp(4.4rem,8.2vw,9.4rem)] leading-[0.9] tracking-[-0.065em]">
                <span className="block text-white/52">The operating layer for</span>
                <span className="block text-white">Secure Enterprise AI.</span>
              </h1>
              <p className="mt-12 max-w-[760px] text-[clamp(1.35rem,2.4vw,2.15rem)] leading-[1.2] tracking-[-0.04em] text-white/90 lg:ml-[10.5rem]">
                <span className="text-white/56">The platform to</span> orchestrate prompt
                review, policy controls, and release approvals into production AI
                workflows.
              </p>
              <div className="mt-12 flex flex-wrap items-center gap-4 lg:ml-[20rem]">
                <LiquidButton onClick={onEnterDashboard}>Book a demo</LiquidButton>
                <LiquidButton onClick={() => scrollToSection('workflows', reduced)} tone="dark" icon>
                  See workflows
                </LiquidButton>
              </div>
            </Reveal>
          </div>

          <HeroTrustRow reduced={reduced} />
        </div>
      </section>

      <section id="workflows" className="bg-[#2f2d2b] px-6 py-16 sm:px-10 lg:px-12 lg:py-20">
        <div className="mx-auto max-w-[1800px]">
          <Reveal reduced={reduced}>
            <h2 className="max-w-[980px] text-[clamp(2.75rem,5vw,4.3rem)] font-medium leading-[1.02] tracking-[-0.06em] text-white">
              The workflows teams operationalize first.
            </h2>
          </Reveal>
          <div className="mt-12 grid gap-4 xl:grid-cols-4">
            {WORKFLOW_CARDS.map((card, index) => (
              <WorkflowCard
                key={card.id}
                card={card}
                reduced={reduced}
                delay={index * 0.08}
              />
            ))}
          </div>
        </div>
      </section>

      <section className="bg-[#2f2d2b] px-6 pb-6 sm:px-10 lg:px-12 lg:pb-10">
        <div className="mx-auto max-w-[1800px]">
          <div className="grid gap-4 xl:grid-cols-3">
            {METRICS.map((item, index) => (
              <MetricCard
                key={item.stat}
                item={item}
                reduced={reduced}
                delay={index * 0.08}
              />
            ))}
          </div>
        </div>
      </section>

      <section id="proof" className="bg-[#efece6] px-4 py-8 sm:px-8 lg:px-12 lg:py-10">
        <div className="mx-auto max-w-[1700px] overflow-hidden border border-black/6 bg-[#f8f5f0] text-[#231f1b] shadow-[0_26px_90px_rgba(39,28,16,0.08)]">
          <div className="grid border-b border-black/6 lg:grid-cols-2">
            {TESTIMONIALS.map((testimonial, index) => (
              <TestimonialCard
                key={testimonial.name}
                testimonial={testimonial}
                reduced={reduced}
                delay={index * 0.08}
              />
            ))}
          </div>

          <Reveal reduced={reduced} className="overflow-x-auto border-b border-black/6">
            <div className="min-w-[920px] px-4 py-4 sm:px-6">
              <div className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 px-4 py-3 text-[11px] uppercase tracking-[0.12em] text-[#9b938b]">
                <div />
                <div>Before</div>
                <div>With PromptShield</div>
                <div>Result</div>
              </div>
              {RESULTS.map((row) => (
                <div
                  key={row.workflow}
                  className="grid grid-cols-[1.9fr,0.55fr,0.55fr,0.75fr] gap-4 border-t border-black/6 px-4 py-4"
                >
                  <div>
                    <div className="text-[15px] font-medium tracking-[-0.02em] text-[#2d2721]">
                      {row.workflow}
                    </div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#8e867f]">
                    <div className="text-[11px] uppercase tracking-[0.1em]">{row.beforeLabel}</div>
                    <div className="mt-1 text-[#5b534b]">{row.before}</div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#8e867f]">
                    <div className="text-[11px] uppercase tracking-[0.1em]">{row.afterLabel}</div>
                    <div className="mt-1 font-medium text-[#2b2620]">{row.after}</div>
                  </div>
                  <div className="text-[13px] leading-[1.35] text-[#ff7641]">{row.result}</div>
                </div>
              ))}
            </div>
          </Reveal>

          <div className="grid border-b border-black/6 lg:grid-cols-3">
            {OUTCOMES.map((outcome, index) => (
              <Reveal key={outcome.title} reduced={reduced} delay={index * 0.08} className="h-full">
                <article className="flex h-full flex-col border-r border-black/6 px-6 py-6 last:border-r-0 lg:px-7">
                  <h3 className="max-w-[22ch] text-[21px] leading-[1.2] tracking-[-0.03em] text-[#2d2721]">
                    {outcome.title}
                  </h3>
                  <div className="mt-16 text-[42px] font-medium tracking-[-0.05em] text-[#342d27]">
                    {outcome.stat}
                  </div>
                  <div className="mt-1 text-[13px] text-[#8b837c]">{outcome.detail}</div>
                </article>
              </Reveal>
            ))}
          </div>

          <div
            id="security"
            className="grid gap-8 px-6 py-7 sm:px-8 lg:grid-cols-[1.3fr,1fr] lg:gap-12"
          >
            <Reveal reduced={reduced}>
              <div className="flex items-center gap-3 text-[24px] font-medium tracking-[-0.04em] text-[#2f2923]">
                <ShieldCheck className="h-5 w-5 text-[#2f2923]" />
                <span>Enterprise-grade security</span>
              </div>
              <p className="mt-3 max-w-[64ch] text-[15px] leading-[1.6] text-[#776e66]">
                Your data stays yours. PromptShield keeps review artifacts isolated,
                preserves auditability, and never trains on your private releases.
              </p>
              <button className="mt-5 inline-flex items-center gap-2 text-[13px] font-semibold tracking-[-0.02em] text-[#2d2721]">
                <span>Security &amp; Trust Center</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </Reveal>

            <Reveal reduced={reduced} delay={0.08}>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                {SECURITY_BADGES.map((badge) => (
                  <div
                    key={badge}
                    className="grid min-h-[92px] place-items-center border border-black/6 bg-white/55 px-3 text-center text-[14px] font-semibold tracking-[0.04em] text-[#433b34]"
                  >
                    {badge}
                  </div>
                ))}
              </div>
            </Reveal>
          </div>

          <Reveal reduced={reduced} className="border-t border-black/6 px-5 py-4 sm:px-8">
            <div className="grid gap-3 text-[12px] text-[#6f665e] sm:grid-cols-2 xl:grid-cols-6">
              {[
                'Audited & tested',
                'Fine-grained access controls',
                'Modern secure practices',
                'Audit logs across every workflow',
                'No training on your data',
                'Regional deployment options',
              ].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#2f2923]" />
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
              Deploy across the team.
              <br />
              Improve over time.
            </h2>
            <div className="mt-10">
              <LiquidButton onClick={onEnterScan}>Request a demo</LiquidButton>
            </div>
          </Reveal>
        </div>
      </section>

      <footer className="bg-[#30302e] px-6 py-12 text-white/78 sm:px-10 lg:px-12 lg:py-14">
        <div className="mx-auto grid max-w-[1700px] gap-12 lg:grid-cols-[1.15fr_repeat(5,0.72fr)]">
          <div>
            <div className="text-[22px] font-semibold tracking-[0.08em] text-white">PS</div>
            <div className="mt-8 max-w-[12ch] text-[clamp(2rem,3vw,3.2rem)] leading-[1.02] tracking-[-0.05em] text-white">
              AI platform purpose-built for security teams.
            </div>
            <div className="mt-8">
              <LiquidButton onClick={onEnterDashboard}>Book a demo</LiquidButton>
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
