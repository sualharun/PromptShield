import React, { useEffect, useMemo, useRef, useState } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import { ArrowRight, Shield } from 'lucide-react'
import { Button } from './button.jsx'
import { AnimatedGroup } from './animated-group.jsx'

const transitionVariants = {
  item: {
    hidden: { opacity: 0, filter: 'blur(12px)', y: 12 },
    visible: {
      opacity: 1,
      filter: 'blur(0px)',
      y: 0,
      transition: { type: 'spring', bounce: 0.3, duration: 1.2 },
    },
  },
}

const THREAT_EVENTS = [
  { text: 'PR #247 — prompt injection blocked', severity: 'critical', repo: 'acme/billing-api' },
  { text: 'PR #103 — secret leak detected in system prompt', severity: 'high', repo: 'acme/ml-pipeline' },
  { text: 'PR #89 — jailbreak attempt flagged', severity: 'critical', repo: 'acme/chatbot-v2' },
  { text: 'PR #312 — role confusion pattern found', severity: 'medium', repo: 'acme/auth-service' },
  { text: 'PR #156 — data leakage via LLM context', severity: 'high', repo: 'acme/rag-engine' },
  { text: 'PR #421 — unsafe template interpolation', severity: 'medium', repo: 'acme/agent-toolkit' },
  { text: 'PR #78 — CVE-2024-3456 in langchain 0.1.2', severity: 'critical', repo: 'acme/llm-proxy' },
  { text: 'PR #199 — system prompt exposed to user input', severity: 'high', repo: 'acme/support-bot' },
]

const SEVERITY_COLORS = {
  critical: '#da1e28',
  high: '#ff832b',
  medium: '#f1c21b',
  low: '#0f62fe',
}

const RING_LABELS = [
  { label: 'Injection', angle: -30, severity: 'critical' },
  { label: 'Secrets', angle: 30, severity: 'high' },
  { label: 'Jailbreak', angle: 90, severity: 'critical' },
  { label: 'Leakage', angle: 150, severity: 'medium' },
  { label: 'Role confusion', angle: 210, severity: 'high' },
  { label: 'Policy gate', angle: 270, severity: 'low' },
]

function ThreatPulseRings({ reduced }) {
  return (
    <div className="absolute inset-0 flex items-center justify-center">
      {[1, 2, 3, 4].map((i) => (
        <motion.div
          key={i}
          className="absolute rounded-full border"
          style={{
            width: `${i * 25}%`,
            height: `${i * 25}%`,
            borderColor: `rgba(69, 137, 255, ${0.18 - i * 0.03})`,
          }}
          animate={
            reduced
              ? { opacity: 0.15 }
              : {
                  scale: [1, 1.04, 1],
                  opacity: [0.15, 0.25, 0.15],
                }
          }
          transition={{
            duration: 3 + i * 0.5,
            repeat: Infinity,
            ease: 'easeInOut',
            delay: i * 0.4,
          }}
        />
      ))}
    </div>
  )
}

function ScanBeam({ reduced }) {
  if (reduced) return null
  return (
    <motion.div
      className="absolute left-1/2 top-1/2 h-px origin-left"
      style={{ width: '42%' }}
      animate={{ rotate: [0, 360] }}
      transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
    >
      <div className="h-px w-full bg-gradient-to-r from-ibm-blue-50/60 via-ibm-blue-40/30 to-transparent" />
      <motion.div
        className="absolute right-0 top-1/2 -translate-y-1/2"
        animate={{ opacity: [0.4, 1, 0.4] }}
        transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
      >
        <div className="h-1.5 w-1.5 rounded-full bg-ibm-blue-40 shadow-[0_0_8px_rgba(120,169,255,0.8)]" />
      </motion.div>
    </motion.div>
  )
}

function FloatingChips({ reduced }) {
  return (
    <>
      {RING_LABELS.map((item, i) => {
        const rad = (item.angle * Math.PI) / 180
        const radius = 40
        const x = Math.cos(rad) * radius
        const y = Math.sin(rad) * radius
        return (
          <motion.div
            key={item.label}
            className="absolute left-1/2 top-1/2 z-10"
            style={{ x: `calc(${x}% - 50%)`, y: `calc(${y}% - 50%)` }}
            initial={{ opacity: 0, scale: 0.8 }}
            animate={
              reduced
                ? { opacity: 0.9, scale: 1 }
                : {
                    opacity: [0.7, 1, 0.7],
                    scale: [0.97, 1.02, 0.97],
                    y: `calc(${y}% - 50% + ${Math.sin(i) * 3}px)`,
                  }
            }
            transition={{
              duration: 3 + i * 0.3,
              repeat: Infinity,
              ease: 'easeInOut',
              delay: i * 0.2,
            }}
          >
            <div
              className="flex items-center gap-1.5 border border-carbon-border bg-ibm-gray-100/90 px-2 py-1 text-[10px] font-medium uppercase tracking-wider backdrop-blur-sm"
              style={{ color: SEVERITY_COLORS[item.severity] }}
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: SEVERITY_COLORS[item.severity] }}
              />
              {item.label}
            </div>
          </motion.div>
        )
      })}
    </>
  )
}

function CenterShield({ reduced }) {
  return (
    <div className="absolute left-1/2 top-1/2 z-20 -translate-x-1/2 -translate-y-1/2">
      <motion.div
        className="flex h-16 w-16 items-center justify-center border border-ibm-blue-60/40 bg-ibm-gray-100"
        animate={
          reduced
            ? {}
            : {
                boxShadow: [
                  '0 0 20px rgba(69,137,255,0.15), 0 0 60px rgba(69,137,255,0.05)',
                  '0 0 30px rgba(69,137,255,0.3), 0 0 80px rgba(69,137,255,0.1)',
                  '0 0 20px rgba(69,137,255,0.15), 0 0 60px rgba(69,137,255,0.05)',
                ],
              }
        }
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
      >
        <Shield className="h-7 w-7 text-ibm-blue-40" />
      </motion.div>
      <div className="mt-2 text-center text-[9px] font-semibold uppercase tracking-[0.2em] text-ibm-blue-40">
        Scanning
      </div>
    </div>
  )
}

function SecurityVisual({ reduced }) {
  return (
    <div className="relative mx-auto aspect-square w-full max-w-md">
      <ThreatPulseRings reduced={reduced} />
      <ScanBeam reduced={reduced} />
      <FloatingChips reduced={reduced} />
      <CenterShield reduced={reduced} />
      <div className="absolute inset-0 rounded-full bg-[radial-gradient(circle,rgba(69,137,255,0.06)_0%,transparent_70%)]" />
    </div>
  )
}

function EventTicker({ reduced }) {
  const doubled = useMemo(() => [...THREAT_EVENTS, ...THREAT_EVENTS], [])

  return (
    <div className="relative overflow-hidden border-y border-carbon-border bg-ibm-gray-100/80">
      <div className="absolute left-0 top-0 z-10 h-full w-16 bg-gradient-to-r from-carbon-bg to-transparent" />
      <div className="absolute right-0 top-0 z-10 h-full w-16 bg-gradient-to-l from-carbon-bg to-transparent" />
      <motion.div
        className="flex gap-8 whitespace-nowrap px-4 py-2.5"
        animate={reduced ? {} : { x: ['0%', '-50%'] }}
        transition={{ duration: 40, repeat: Infinity, ease: 'linear' }}
      >
        {doubled.map((evt, i) => (
          <span key={i} className="inline-flex items-center gap-2 text-[11px]">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[evt.severity] }}
            />
            <span className="font-mono text-carbon-text-tertiary">{evt.repo}</span>
            <span className="text-carbon-text-secondary">{evt.text}</span>
          </span>
        ))}
      </motion.div>
    </div>
  )
}

function WhyCard({ title, description, accent }) {
  return (
    <motion.div
      className="group relative border border-carbon-border bg-ibm-gray-100 p-5 transition-colors hover:border-ibm-blue-60/40"
      whileHover={{ y: -3, transition: { duration: 0.2 } }}
    >
      <div
        className="absolute left-0 top-0 h-full w-0.5 transition-all group-hover:shadow-[0_0_12px_rgba(69,137,255,0.4)]"
        style={{ backgroundColor: accent }}
      />
      <h3 className="text-[13px] font-semibold text-carbon-text">{title}</h3>
      <p className="mt-2 text-[12px] leading-relaxed text-carbon-text-secondary">{description}</p>
    </motion.div>
  )
}

function StatusIndicator({ reduced }) {
  const [count, setCount] = useState(0)

  useEffect(() => {
    if (reduced) return
    const id = setInterval(() => setCount((c) => c + 1), 3000)
    return () => clearInterval(id)
  }, [reduced])

  return (
    <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.15em] text-ibm-green-50">
      <motion.span
        className="h-1.5 w-1.5 rounded-full bg-ibm-green-50"
        animate={reduced ? {} : { opacity: [1, 0.3, 1] }}
        transition={{ duration: 2, repeat: Infinity }}
      />
      <span>Live monitoring active</span>
      <AnimatePresence mode="wait">
        <motion.span
          key={count}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 0.5, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          className="font-mono text-carbon-text-tertiary"
        >
          {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </motion.span>
      </AnimatePresence>
    </div>
  )
}

export function HeroSection({ onPrimary, onSecondary }) {
  const reduced = useReducedMotion()

  return (
    <>
      <HeroHeader onPrimary={onPrimary} />

      <main className="overflow-hidden pt-20 md:pt-24">
        {/* Ambient background */}
        <div aria-hidden className="pointer-events-none fixed inset-0 -z-10">
          <div className="absolute left-1/4 top-0 h-[60rem] w-[40rem] -rotate-12 bg-[radial-gradient(ellipse,rgba(69,137,255,0.08)_0%,transparent_60%)]" />
          <div className="absolute right-0 top-1/4 h-[50rem] w-[35rem] rotate-12 bg-[radial-gradient(ellipse,rgba(138,63,252,0.06)_0%,transparent_60%)]" />
        </div>

        {/* Hero block */}
        <section className="relative px-6 pb-12 pt-8 md:pb-16 md:pt-12">
          <div className="mx-auto max-w-7xl">
            <div className="grid items-center gap-8 lg:grid-cols-[1fr,460px] lg:gap-12">
              {/* Left: copy */}
              <div>
                <AnimatedGroup
                  variants={{
                    container: {
                      visible: { transition: { staggerChildren: 0.08, delayChildren: 0.1 } },
                    },
                    ...transitionVariants,
                  }}
                >
                  <div className="flex items-center gap-3">
                    <StatusIndicator reduced={reduced} />
                  </div>

                  <h1 className="mt-6 max-w-2xl text-4xl font-light leading-[1.08] text-carbon-text md:text-6xl xl:text-[4.5rem]">
                    AI security gate
                    <br />
                    <span className="text-ibm-blue-40">before production</span>
                  </h1>

                  <p className="mt-6 max-w-xl text-base leading-relaxed text-carbon-text-secondary md:text-lg">
                    PromptShield scans every pull request for prompt injection, secret
                    leakage, jailbreak vectors, and role confusion — then blocks risky
                    merges with explainable risk scores and remediation.
                  </p>

                  <div className="mt-8 flex flex-wrap items-center gap-3">
                    <div className="border border-ibm-blue-50/40 p-0.5">
                      <Button
                        size="lg"
                        className="rounded-none px-6 text-base"
                        onClick={onPrimary}
                      >
                        <span className="text-nowrap">Open Dashboard</span>
                      </Button>
                    </div>
                    <Button
                      size="lg"
                      variant="outline"
                      className="rounded-none px-6"
                      onClick={onSecondary}
                    >
                      <span className="text-nowrap">Run Live Scan</span>
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </div>

                  <div className="mt-8 flex flex-wrap gap-6 text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary">
                    <span>7 detection categories</span>
                    <span className="text-carbon-border">|</span>
                    <span>CWE + OWASP mapped</span>
                    <span className="text-carbon-border">|</span>
                    <span>96% F1 benchmark</span>
                  </div>
                </AnimatedGroup>
              </div>

              {/* Right: animated visual */}
              <motion.div
                className="relative"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.8, delay: 0.3 }}
              >
                <div className="relative border border-carbon-border bg-ibm-gray-100/50 p-6">
                  <div className="absolute -inset-px bg-gradient-to-br from-ibm-blue-60/10 via-transparent to-ibm-purple-60/10" />
                  <div className="relative">
                    <div className="mb-3 flex items-center justify-between">
                      <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-carbon-text-tertiary">
                        Threat radar — real-time
                      </span>
                      <span className="border border-carbon-border bg-ibm-gray-100 px-2 py-0.5 text-[9px] font-medium uppercase tracking-wider text-ibm-blue-40">
                        Active
                      </span>
                    </div>
                    <SecurityVisual reduced={reduced} />
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        </section>

        {/* Event ticker */}
        <EventTicker reduced={reduced} />

        {/* Why it wins — for judges */}
        <section className="mx-auto max-w-7xl px-6 py-14" id="landing-pipeline">
          <AnimatedGroup
            variants={{
              container: {
                visible: { transition: { staggerChildren: 0.06, delayChildren: 0.1 } },
              },
              ...transitionVariants,
            }}
          >
            <div className="mb-8">
              <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-40">
                Why this wins
              </p>
              <h2 className="mt-2 text-2xl font-light text-carbon-text md:text-3xl">
                What makes PromptShield different
              </h2>
            </div>

            <div className="grid gap-px bg-carbon-border md:grid-cols-2 lg:grid-cols-4">
              <WhyCard
                title="Shift-left, not runtime"
                description="Catches prompt vulnerabilities during code review — before risky code reaches production. No runtime overhead."
                accent="#0f62fe"
              />
              <WhyCard
                title="Hybrid detection engine"
                description="AST-based dataflow taint analysis + regex patterns + LLM semantic audit running in parallel for maximum coverage."
                accent="#8a3ffc"
              />
              <WhyCard
                title="Explainable risk scores"
                description="Every score breaks down by category with confidence levels and plain-english reasoning. No black-box numbers."
                accent="#24a148"
              />
              <WhyCard
                title="Policy-as-code gates"
                description="Per-repo .promptshield.yml controls thresholds, severity overrides, and ignore rules. Integrates with existing CI."
                accent="#ff832b"
              />
            </div>
          </AnimatedGroup>
        </section>

        {/* Proof strip */}
        <section className="border-t border-carbon-border bg-ibm-gray-100/50 py-10">
          <div className="mx-auto max-w-7xl px-6">
            <div className="grid gap-8 md:grid-cols-3">
              <div className="text-center">
                <div className="text-3xl font-light tabular-nums text-carbon-text">96%</div>
                <div className="mt-1 text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary">
                  F1 score on 100-sample benchmark
                </div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-light tabular-nums text-carbon-text">14</div>
                <div className="mt-1 text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary">
                  Jailbreak attack payloads tested
                </div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-light tabular-nums text-ibm-blue-40">7</div>
                <div className="mt-1 text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary">
                  Detection categories · CWE + OWASP mapped
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </>
  )
}

function HeroHeader({ onPrimary }) {
  const [menuOpen, setMenuOpen] = React.useState(false)
  const [scrolled, setScrolled] = React.useState(false)

  React.useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <header>
      <nav className="fixed z-30 w-full px-2">
        <div
          className={`mx-auto mt-2 max-w-6xl border border-carbon-border bg-carbon-bg px-4 transition-all duration-300 md:px-6 ${
            scrolled ? 'max-w-5xl bg-ibm-gray-100/95 backdrop-blur-md' : ''
          }`}
        >
          <div className="relative flex items-center justify-between py-3">
            <a href="#" aria-label="home" className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-ibm-blue-40" />
              <span className="text-sm font-semibold tracking-[0.06em] text-carbon-text">
                PromptShield
              </span>
            </a>

            <div className="hidden items-center gap-6 text-xs uppercase tracking-[0.1em] text-carbon-text-secondary lg:flex">
              <a href="#landing-pipeline" className="transition-colors hover:text-carbon-text">
                Detection
              </a>
              <a href="#" className="transition-colors hover:text-carbon-text">
                Docs
              </a>
              <a href="#" className="transition-colors hover:text-carbon-text">
                GitHub
              </a>
            </div>

            <div className="hidden items-center gap-2 lg:flex">
              <Button size="sm" className="rounded-none" onClick={onPrimary}>
                Get Started
              </Button>
            </div>

            <button
              onClick={() => setMenuOpen(!menuOpen)}
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              className="p-2 lg:hidden"
            >
              <div className="flex h-4 w-5 flex-col justify-center gap-1">
                <span
                  className={`block h-px w-full bg-carbon-text transition-transform ${
                    menuOpen ? 'translate-y-[3px] rotate-45' : ''
                  }`}
                />
                <span
                  className={`block h-px w-full bg-carbon-text transition-transform ${
                    menuOpen ? '-translate-y-[1px] -rotate-45' : ''
                  }`}
                />
              </div>
            </button>
          </div>

          {menuOpen && (
            <div className="border-t border-carbon-border pb-4 pt-3 lg:hidden">
              <div className="space-y-3 text-sm text-carbon-text-secondary">
                <a href="#landing-pipeline" className="block hover:text-carbon-text">Detection</a>
                <a href="#" className="block hover:text-carbon-text">Docs</a>
                <a href="#" className="block hover:text-carbon-text">GitHub</a>
              </div>
              <div className="mt-3">
                <Button size="sm" className="rounded-none" onClick={onPrimary}>
                  Get Started
                </Button>
              </div>
            </div>
          )}
        </div>
      </nav>
    </header>
  )
}
