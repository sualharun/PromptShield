import { motion, useTransform } from 'framer-motion'

const INSTALL_URL = import.meta.env?.VITE_GITHUB_APP_INSTALL_URL || '#'

export default function CTACluster({ scrollProgress, onDashboard, onScan }) {
  const ctaOpacity = useTransform(scrollProgress, [0.0, 0.16, 0.22], [1, 1, 0])
  const ctaY = useTransform(scrollProgress, [0.0, 0.08], [0, 0])

  return (
    <motion.div
      className="flex flex-wrap items-center justify-center gap-3 md:justify-start"
      style={{ opacity: ctaOpacity, y: ctaY }}
    >
      <a
        href={INSTALL_URL}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-2 rounded-full bg-carbon-text px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-black/10 transition-all hover:scale-[1.02] hover:shadow-xl"
      >
        Install GitHub App
        <span className="text-base leading-none">→</span>
      </a>
      <button
        onClick={onDashboard}
        className="inline-flex items-center gap-2 rounded-full border border-carbon-border bg-white/90 px-6 py-3 text-sm font-semibold text-carbon-text backdrop-blur transition-all hover:scale-[1.01] hover:bg-white"
      >
        Go to dashboard
      </button>
      <button
        onClick={onScan}
        className="text-sm font-medium text-ibm-blue-70 transition-colors hover:text-ibm-blue-80"
      >
        Run a scan →
      </button>
    </motion.div>
  )
}
