import { useEffect, useState, useMemo } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  ArrowRight,
  GitPullRequest,
  Network,
  FileText,
  Zap,
  Lock,
  Target,
  AlertTriangle,
  CheckCircle2,
  Github,
  MessageSquare,
  Workflow,
  ExternalLink,
  ChevronRight,
  Play,
} from 'lucide-react'
import { Button } from '../components/ui/button.jsx'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

// Animation variants
const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: 'easeOut' } },
}

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.1 },
  },
}

// Animated number component
function AnimatedNumber({ value, suffix = '', reduced }) {
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    if (reduced || value === 0) {
      setDisplay(value)
      return
    }
    let frame
    const start = performance.now()
    const duration = 1200
    const tick = (now) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(value * eased))
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, reduced])

  return (
    <>
      {display.toLocaleString()}
      {suffix}
    </>
  )
}

// Navigation component
function Navigation({ onScan, onDashboard }) {
  const [scrolled, setScrolled] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'border-b border-carbon-border bg-ibm-gray-100/95 backdrop-blur-md'
          : 'bg-transparent'
      }`}
    >
      <div className="mx-auto max-w-7xl px-6">
        <nav className="flex h-14 items-center justify-between">
          {/* Logo */}
          <a href="#" className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center bg-ibm-blue-60">
              <Shield className="h-4.5 w-4.5 text-white" />
            </div>
            <span className="text-[15px] font-semibold tracking-tight text-carbon-text">
              PromptShield
            </span>
          </a>

          {/* Desktop Nav Links */}
          <div className="hidden items-center gap-8 lg:flex">
            <a
              href="#features"
              className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text"
            >
              Features
            </a>
            <a
              href="#use-cases"
              className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text"
            >
              Use Cases
            </a>
            <button
              onClick={onDashboard}
              className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text"
            >
              Dashboard
            </button>
            <a
              href="#"
              className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text"
            >
              Docs
            </a>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text"
            >
              GitHub
            </a>
          </div>

          {/* Desktop CTA */}
          <div className="hidden items-center gap-3 lg:flex">
            <button className="text-[13px] text-carbon-text-secondary transition-colors hover:text-carbon-text">
              Log in
            </button>
            <Button size="sm" onClick={onScan}>
              Sign up
            </Button>
          </div>

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 lg:hidden"
            aria-label="Toggle menu"
          >
            <div className="flex h-4 w-5 flex-col justify-center gap-1.5">
              <span
                className={`block h-px w-full bg-carbon-text transition-transform ${
                  mobileMenuOpen ? 'translate-y-[4px] rotate-45' : ''
                }`}
              />
              <span
                className={`block h-px w-full bg-carbon-text transition-transform ${
                  mobileMenuOpen ? '-translate-y-[2px] -rotate-45' : ''
                }`}
              />
            </div>
          </button>
        </nav>

        {/* Mobile menu */}
        <AnimatePresence>
          {mobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="border-t border-carbon-border lg:hidden"
            >
              <div className="flex flex-col gap-4 py-6">
                <a href="#features" className="text-sm text-carbon-text-secondary">
                  Features
                </a>
                <a href="#use-cases" className="text-sm text-carbon-text-secondary">
                  Use Cases
                </a>
                <button
                  onClick={onDashboard}
                  className="text-left text-sm text-carbon-text-secondary"
                >
                  Dashboard
                </button>
                <a href="#" className="text-sm text-carbon-text-secondary">
                  Docs
                </a>
                <div className="flex gap-3 pt-4">
                  <Button variant="outline" className="flex-1" onClick={onScan}>
                    Log in
                  </Button>
                  <Button className="flex-1" onClick={onScan}>
                    Sign up
                  </Button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.header>
  )
}

// Hero Section
function HeroSection({ onScan, onDashboard, reduced }) {
  return (
    <section className="relative overflow-hidden pt-32 pb-20 md:pt-40 md:pb-28">
      {/* Background gradient */}
      <div className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute left-1/4 top-0 h-[800px] w-[600px] -rotate-12 bg-[radial-gradient(ellipse,rgba(15,98,254,0.12)_0%,transparent_60%)]" />
        <div className="absolute right-0 top-1/4 h-[600px] w-[500px] rotate-12 bg-[radial-gradient(ellipse,rgba(138,63,252,0.08)_0%,transparent_60%)]" />
      </div>

      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          animate="visible"
          className="text-center"
        >
          {/* Badge */}
          <motion.div variants={fadeInUp} className="mb-6 inline-flex items-center gap-2">
            <span className="inline-flex items-center gap-2 border border-ibm-blue-60/30 bg-ibm-blue-60/10 px-3 py-1.5 text-[11px] font-medium uppercase tracking-wider text-ibm-blue-40">
              <span className="h-1.5 w-1.5 rounded-full bg-ibm-green-50 animate-pulse" />
              Enterprise Security
            </span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            variants={fadeInUp}
            className="mx-auto max-w-4xl text-4xl font-light leading-[1.1] tracking-tight text-carbon-text md:text-6xl lg:text-7xl"
          >
            Enterprise LLM
            <br />
            <span className="text-ibm-blue-40">Security Scanning</span>
          </motion.h1>

          {/* Subheading */}
          <motion.p
            variants={fadeInUp}
            className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-carbon-text-secondary md:text-xl"
          >
            Detect prompt injection, jailbreaks, and data exfiltration in real-time.
            Protect your AI pipelines before vulnerabilities reach production.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            variants={fadeInUp}
            className="mt-10 flex flex-wrap items-center justify-center gap-4"
          >
            <div className="border border-ibm-blue-50/40 p-0.5">
              <Button size="lg" className="px-8" onClick={onScan}>
                Start Free Scan
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
            <Button size="lg" variant="outline" className="gap-2" onClick={onDashboard}>
              <Play className="h-4 w-4" />
              View Demo
            </Button>
          </motion.div>

          {/* Trust badges */}
          <motion.div
            variants={fadeInUp}
            className="mt-12 flex flex-wrap items-center justify-center gap-6 text-[11px] uppercase tracking-[0.1em] text-carbon-text-tertiary"
          >
            <span className="flex items-center gap-2">
              <CheckCircle2 className="h-3.5 w-3.5 text-ibm-green-50" />
              SOC 2 Compliant
            </span>
            <span className="hidden text-carbon-border md:inline">|</span>
            <span className="flex items-center gap-2">
              <CheckCircle2 className="h-3.5 w-3.5 text-ibm-green-50" />
              OWASP Aligned
            </span>
            <span className="hidden text-carbon-border md:inline">|</span>
            <span className="flex items-center gap-2">
              <CheckCircle2 className="h-3.5 w-3.5 text-ibm-green-50" />
              Open Source
            </span>
          </motion.div>
        </motion.div>

        {/* Hero Visual */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mt-16 md:mt-20"
        >
          <div className="relative mx-auto max-w-5xl">
            <div className="relative overflow-hidden border border-carbon-border bg-ibm-gray-100/80 p-1">
              {/* Browser chrome */}
              <div className="flex items-center gap-2 border-b border-carbon-border bg-ibm-gray-90 px-4 py-3">
                <div className="flex gap-1.5">
                  <div className="h-2.5 w-2.5 rounded-full bg-ibm-red-60" />
                  <div className="h-2.5 w-2.5 rounded-full bg-ibm-yellow-30" />
                  <div className="h-2.5 w-2.5 rounded-full bg-ibm-green-50" />
                </div>
                <div className="ml-4 flex-1 rounded-sm bg-ibm-gray-100 px-3 py-1.5 text-[11px] text-carbon-text-tertiary">
                  promptshield.io/dashboard
                </div>
              </div>
              {/* Dashboard preview */}
              <div className="bg-carbon-bg p-6">
                <DashboardPreview reduced={reduced} />
              </div>
            </div>
            {/* Glow effect */}
            <div className="absolute -inset-4 -z-10 bg-gradient-to-b from-ibm-blue-60/20 via-transparent to-transparent blur-3xl" />
          </div>
        </motion.div>
      </div>
    </section>
  )
}

// Dashboard Preview Component
function DashboardPreview({ reduced }) {
  return (
    <div className="grid gap-4 md:grid-cols-4">
      {/* Stats cards */}
      {[
        { label: 'Total Scans', value: 1247, trend: '+12%' },
        { label: 'Threats Blocked', value: 89, trend: '+5%', color: 'text-ibm-red-50' },
        { label: 'Repos Protected', value: 34, trend: '+3' },
        { label: 'Risk Score', value: 24, suffix: '/100', color: 'text-ibm-green-50' },
      ].map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 + i * 0.1 }}
          className="border border-carbon-border bg-ibm-gray-100 p-4"
        >
          <div className="text-[10px] font-medium uppercase tracking-wider text-carbon-text-tertiary">
            {stat.label}
          </div>
          <div className={`mt-2 text-2xl font-light tabular-nums ${stat.color || 'text-carbon-text'}`}>
            <AnimatedNumber value={stat.value} suffix={stat.suffix} reduced={reduced} />
          </div>
          <div className="mt-1 text-[10px] text-ibm-green-50">{stat.trend}</div>
        </motion.div>
      ))}
    </div>
  )
}

// Statistics Section
function StatisticsSection({ reduced }) {
  const stats = [
    { value: 500, suffix: '+', label: 'LLM Attack Patterns Detected' },
    { value: 89, suffix: '%', label: 'F1 Score on Benchmark' },
    { value: 10, suffix: 'K+', label: 'PRs Scanned' },
    { value: 50, suffix: '+', label: 'Fortune 500 Companies' },
  ]

  return (
    <section className="border-y border-carbon-border bg-ibm-gray-100/50 py-16">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
          variants={staggerContainer}
          className="grid gap-8 md:grid-cols-4"
        >
          {stats.map((stat, i) => (
            <motion.div key={stat.label} variants={fadeInUp} className="text-center">
              <div className="text-4xl font-light tabular-nums text-carbon-text md:text-5xl">
                <AnimatedNumber value={stat.value} suffix={stat.suffix} reduced={reduced} />
              </div>
              <div className="mt-2 text-[12px] uppercase tracking-[0.1em] text-carbon-text-tertiary">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  )
}

// Features Section
function FeaturesSection() {
  const features = [
    {
      icon: Network,
      title: 'Dependency Risk Graph',
      description:
        'Visualize and analyze complex dependency chains to identify hidden vulnerabilities in your LLM supply chain.',
      color: 'text-ibm-blue-40',
      bgColor: 'bg-ibm-blue-60/10',
    },
    {
      icon: GitPullRequest,
      title: 'Real-time PR Scanning',
      description:
        'Automatically scan every pull request for prompt injection, jailbreaks, and data exfiltration before merge.',
      color: 'text-ibm-purple-40',
      bgColor: 'bg-ibm-purple-60/10',
    },
    {
      icon: FileText,
      title: 'Executive Risk Briefs',
      description:
        'Generate professional security reports with actionable insights for stakeholders and compliance teams.',
      color: 'text-ibm-green-50',
      bgColor: 'bg-ibm-green-50/10',
    },
  ]

  return (
    <section id="features" className="py-24">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
          variants={staggerContainer}
        >
          {/* Section header */}
          <motion.div variants={fadeInUp} className="mb-16 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-40">
              Core Features
            </p>
            <h2 className="mt-3 text-3xl font-light text-carbon-text md:text-4xl">
              Enterprise-grade security for AI
            </h2>
            <p className="mx-auto mt-4 max-w-2xl text-carbon-text-secondary">
              Built for security teams who need comprehensive visibility into their LLM pipelines
            </p>
          </motion.div>

          {/* Feature cards */}
          <div className="grid gap-6 md:grid-cols-3">
            {features.map((feature) => (
              <motion.div
                key={feature.title}
                variants={fadeInUp}
                whileHover={{ y: -4, transition: { duration: 0.2 } }}
                className="group relative border border-carbon-border bg-ibm-gray-100 p-8 transition-colors hover:border-ibm-blue-60/40"
              >
                <div className="absolute left-0 top-0 h-full w-1 bg-carbon-border transition-all group-hover:bg-ibm-blue-60 group-hover:shadow-[0_0_12px_rgba(15,98,254,0.4)]" />
                <div className={`mb-5 inline-flex h-12 w-12 items-center justify-center ${feature.bgColor}`}>
                  <feature.icon className={`h-6 w-6 ${feature.color}`} />
                </div>
                <h3 className="text-lg font-medium text-carbon-text">{feature.title}</h3>
                <p className="mt-3 text-[14px] leading-relaxed text-carbon-text-secondary">
                  {feature.description}
                </p>
                <a
                  href="#"
                  className="mt-6 inline-flex items-center gap-1 text-[13px] text-ibm-blue-40 transition-colors hover:text-ibm-blue-30"
                >
                  Learn more
                  <ChevronRight className="h-4 w-4" />
                </a>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}

// Use Cases Section
function UseCasesSection() {
  const useCases = [
    {
      icon: Lock,
      title: 'Secure Your AI Pipelines',
      description: 'Prevent prompt injection and jailbreak attacks from compromising your production systems.',
    },
    {
      icon: FileText,
      title: 'Compliance & Governance',
      description: 'Meet SOC 2, OWASP, and industry security standards with automated compliance reporting.',
    },
    {
      icon: Target,
      title: 'Red Team Simulations',
      description: 'Test your defenses with adversarial attack simulations based on real-world threat patterns.',
    },
    {
      icon: AlertTriangle,
      title: 'Supply Chain Risk',
      description: 'Monitor and assess risks from third-party LLM dependencies and model providers.',
    },
  ]

  return (
    <section id="use-cases" className="bg-ibm-gray-100/30 py-24">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
          variants={staggerContainer}
        >
          {/* Section header */}
          <motion.div variants={fadeInUp} className="mb-16 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-40">
              Use Cases
            </p>
            <h2 className="mt-3 text-3xl font-light text-carbon-text md:text-4xl">
              Built for your security needs
            </h2>
          </motion.div>

          {/* Use case cards */}
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {useCases.map((useCase, i) => (
              <motion.div
                key={useCase.title}
                variants={fadeInUp}
                whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
                className="group border border-carbon-border bg-carbon-bg p-6 transition-colors hover:border-ibm-blue-60/40"
              >
                <div className="mb-4 inline-flex h-10 w-10 items-center justify-center border border-carbon-border bg-ibm-gray-100 transition-colors group-hover:border-ibm-blue-60/40">
                  <useCase.icon className="h-5 w-5 text-ibm-blue-40" />
                </div>
                <h3 className="text-[15px] font-medium text-carbon-text">{useCase.title}</h3>
                <p className="mt-2 text-[13px] leading-relaxed text-carbon-text-secondary">
                  {useCase.description}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}

// Integration Logos Section
function IntegrationsSection() {
  const integrations = [
    { name: 'GitHub', icon: Github },
    { name: 'Jira', icon: Workflow },
    { name: 'Slack', icon: MessageSquare },
    { name: 'IBM Watson', icon: Zap },
  ]

  return (
    <section className="border-y border-carbon-border py-16">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
          variants={staggerContainer}
          className="text-center"
        >
          <motion.p
            variants={fadeInUp}
            className="mb-10 text-[11px] font-medium uppercase tracking-[0.14em] text-carbon-text-tertiary"
          >
            Seamless Integrations
          </motion.p>
          <motion.div
            variants={fadeInUp}
            className="flex flex-wrap items-center justify-center gap-12"
          >
            {integrations.map((integration) => (
              <div
                key={integration.name}
                className="flex items-center gap-2 text-carbon-text-secondary transition-colors hover:text-carbon-text"
              >
                <integration.icon className="h-6 w-6" />
                <span className="text-sm font-medium">{integration.name}</span>
              </div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </section>
  )
}

// CTA Section
function CTASection({ onScan }) {
  const [email, setEmail] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (email) {
      onScan()
    }
  }

  return (
    <section className="py-24">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
          variants={staggerContainer}
          className="relative overflow-hidden border border-carbon-border bg-ibm-gray-100 p-12 md:p-16"
        >
          {/* Background accent */}
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-ibm-blue-60/10 via-transparent to-ibm-purple-60/5" />

          <div className="relative text-center">
            <motion.p
              variants={fadeInUp}
              className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-40"
            >
              Get Started Today
            </motion.p>
            <motion.h2
              variants={fadeInUp}
              className="mt-4 text-3xl font-light text-carbon-text md:text-4xl"
            >
              Join 1000+ security teams
            </motion.h2>
            <motion.p
              variants={fadeInUp}
              className="mx-auto mt-4 max-w-lg text-carbon-text-secondary"
            >
              Start protecting your AI pipelines in minutes. No credit card required.
            </motion.p>

            {/* Email signup form */}
            <motion.form
              variants={fadeInUp}
              onSubmit={handleSubmit}
              className="mx-auto mt-8 flex max-w-md flex-col gap-3 sm:flex-row"
            >
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your work email"
                className="flex-1 border border-carbon-border bg-carbon-bg px-4 py-3 text-sm text-carbon-text placeholder:text-carbon-text-tertiary focus:border-ibm-blue-60 focus:outline-none"
              />
              <Button type="submit" size="lg" className="px-8">
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </motion.form>

            {/* Trust note */}
            <motion.p
              variants={fadeInUp}
              className="mt-6 text-[12px] text-carbon-text-tertiary"
            >
              Free 14-day trial. No credit card required.
            </motion.p>
          </div>
        </motion.div>
      </div>
    </section>
  )
}

// Threat Ticker
function ThreatTicker({ reduced }) {
  const threats = useMemo(
    () => [
      { text: 'PR #247 - prompt injection blocked', severity: 'critical', repo: 'acme/billing-api' },
      { text: 'PR #103 - secret leak detected', severity: 'high', repo: 'acme/ml-pipeline' },
      { text: 'PR #89 - jailbreak attempt flagged', severity: 'critical', repo: 'acme/chatbot-v2' },
      { text: 'PR #312 - role confusion pattern found', severity: 'medium', repo: 'acme/auth-service' },
      { text: 'PR #156 - data leakage via LLM context', severity: 'high', repo: 'acme/rag-engine' },
      { text: 'PR #421 - unsafe template interpolation', severity: 'medium', repo: 'acme/agent-toolkit' },
    ],
    []
  )

  const doubled = useMemo(() => [...threats, ...threats], [threats])

  const severityColors = {
    critical: '#da1e28',
    high: '#ff832b',
    medium: '#f1c21b',
  }

  return (
    <div className="relative overflow-hidden border-y border-carbon-border bg-ibm-gray-100/80">
      <div className="pointer-events-none absolute left-0 top-0 z-10 h-full w-24 bg-gradient-to-r from-carbon-bg to-transparent" />
      <div className="pointer-events-none absolute right-0 top-0 z-10 h-full w-24 bg-gradient-to-l from-carbon-bg to-transparent" />
      <motion.div
        className="flex gap-10 whitespace-nowrap px-6 py-3"
        animate={reduced ? {} : { x: ['0%', '-50%'] }}
        transition={{ duration: 30, repeat: Infinity, ease: 'linear' }}
      >
        {doubled.map((threat, i) => (
          <span key={i} className="inline-flex items-center gap-2 text-[11px]">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: severityColors[threat.severity] }}
            />
            <span className="font-mono text-carbon-text-tertiary">{threat.repo}</span>
            <span className="text-carbon-text-secondary">{threat.text}</span>
          </span>
        ))}
      </motion.div>
    </div>
  )
}

// Footer
function Footer() {
  return (
    <footer className="border-t border-carbon-border bg-carbon-bg py-12">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex flex-col items-center justify-between gap-6 md:flex-row">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-ibm-blue-40" />
            <span className="text-sm font-medium text-carbon-text">PromptShield</span>
          </div>
          <div className="flex flex-wrap items-center gap-6 text-[12px] text-carbon-text-tertiary">
            <a href="#" className="transition-colors hover:text-carbon-text">
              Documentation
            </a>
            <a href="#" className="transition-colors hover:text-carbon-text">
              Privacy Policy
            </a>
            <a href="#" className="transition-colors hover:text-carbon-text">
              Terms of Service
            </a>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 transition-colors hover:text-carbon-text"
            >
              GitHub
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <div className="text-[11px] text-carbon-text-tertiary">
            <span className="font-mono">Carbon Design System</span>
          </div>
        </div>
      </div>
    </footer>
  )
}

// Main Landing Page Component
export default function LandingPage({ onEnterDashboard, onEnterScan }) {
  const reduced = useReducedMotion()

  return (
    <div className="min-h-screen bg-carbon-bg">
      <Navigation onScan={onEnterScan} onDashboard={onEnterDashboard} />
      <HeroSection onScan={onEnterScan} onDashboard={onEnterDashboard} reduced={reduced} />
      <ThreatTicker reduced={reduced} />
      <StatisticsSection reduced={reduced} />
      <FeaturesSection />
      <UseCasesSection />
      <IntegrationsSection />
      <CTASection onScan={onEnterScan} />
      <Footer />
    </div>
  )
}
