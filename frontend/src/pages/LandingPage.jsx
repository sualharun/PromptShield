import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Demo } from '../components/blocks/demo.jsx'
import { fetchWithTimeout } from '../lib/fetchWithTimeout.js'

function AnimatedNumber({ value, reduced }) {
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    if (reduced || value === 0) {
      setDisplay(value)
      return
    }
    let frame
    const start = performance.now()
    const duration = 800
    const from = 0
    const tick = (now) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(from + (value - from) * eased))
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, reduced])

  return <>{display}</>
}

function Kpi({ label, value, tone, delay = 0, reduced }) {
  const toneClass =
    tone === 'danger'
      ? 'text-ibm-red-60'
      : tone === 'good'
        ? 'text-ibm-green-50'
        : 'text-carbon-text'

  return (
    <motion.div
      className="group relative border border-carbon-border bg-ibm-gray-100 px-5 py-5 transition-colors hover:border-ibm-blue-60/30"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      whileHover={reduced ? {} : { y: -2 }}
    >
      <div className="absolute left-0 top-0 h-full w-px bg-carbon-border transition-colors group-hover:bg-ibm-blue-60/40" />
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-carbon-text-tertiary">
        {label}
      </div>
      <div className={`mt-2 text-3xl font-light tabular-nums ${toneClass}`}>
        <AnimatedNumber value={value} reduced={reduced} />
      </div>
    </motion.div>
  )
}

export default function LandingPage({ onEnterDashboard, onEnterScan }) {
  const [data, setData] = useState(null)
  const reduced = useReducedMotion()

  useEffect(() => {
    let cancelled = false
    fetchWithTimeout('/api/dashboard/github')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!cancelled) setData(d)
      })
      .catch(() => {
        if (!cancelled) setData(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const sev = data?.severity_totals || { critical: 0, high: 0, medium: 0, low: 0 }
  const criticalHigh = (sev.critical || 0) + (sev.high || 0)

  return (
    <div className="pb-12">
      <Demo onDashboard={onEnterDashboard} onScan={onEnterScan} />

      <section className="mx-auto mt-6 max-w-7xl px-6">
        <div className="mb-4 flex items-center justify-between">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-carbon-text-tertiary">
            Pipeline metrics
          </p>
          <div className="flex items-center gap-2 text-[10px] text-carbon-text-tertiary">
            <span className="h-1 w-1 rounded-full bg-ibm-green-50" />
            <span>Live from GitHub</span>
          </div>
        </div>
        <div className="grid gap-px bg-carbon-border md:grid-cols-4">
          <Kpi
            label="PR scans"
            value={data?.total_pr_scans ?? 0}
            delay={0.1}
            reduced={reduced}
          />
          <Kpi
            label="Repos protected"
            value={data?.repos_covered ?? 0}
            tone="good"
            delay={0.2}
            reduced={reduced}
          />
          <Kpi
            label="Critical + high"
            value={criticalHigh}
            tone={criticalHigh > 0 ? 'danger' : 'neutral'}
            delay={0.3}
            reduced={reduced}
          />
          <Kpi
            label="Gate threshold"
            value={data?.threshold ?? 70}
            delay={0.4}
            reduced={reduced}
          />
        </div>
      </section>
    </div>
  )
}
