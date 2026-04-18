import { motion, useTransform } from 'framer-motion'

const CARDS = [
  { label: 'Prompt injection detected', severity: 'critical', color: 'bg-gradient-to-br from-[#ffd3de] to-[#ffebef] dark:from-red-900/45 dark:to-red-800/25 border-red-200 dark:border-red-800', x: -156, y: -98 },
  { label: 'System prompt leakage', severity: 'high', color: 'bg-gradient-to-br from-[#ffd9bd] to-[#fff0e2] dark:from-orange-900/40 dark:to-orange-800/20 border-orange-200 dark:border-orange-800', x: 96, y: -126 },
  { label: 'Secret in prompt context', severity: 'critical', color: 'bg-gradient-to-br from-[#f0d2ff] to-[#fdeeff] dark:from-fuchsia-900/40 dark:to-fuchsia-800/20 border-fuchsia-200 dark:border-fuchsia-800', x: -74, y: 24 },
  { label: 'Role confusion pattern', severity: 'medium', color: 'bg-gradient-to-br from-[#ffeec3] to-[#fff8e3] dark:from-amber-900/35 dark:to-amber-800/20 border-amber-200 dark:border-amber-800', x: 114, y: 8 },
  { label: 'PII data leakage', severity: 'high', color: 'bg-gradient-to-br from-[#d8ecff] to-[#eef7ff] dark:from-blue-900/35 dark:to-blue-800/20 border-blue-200 dark:border-blue-800', x: -30, y: 132 },
  { label: 'Overly permissive', severity: 'low', color: 'bg-gradient-to-br from-[#dff6f2] to-[#f0fdfa] dark:from-teal-900/35 dark:to-teal-800/20 border-teal-200 dark:border-teal-800', x: 170, y: 108 },
]

const SEV_DOT = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-blue-500',
}

function TaskCard({ card, index, scrollProgress }) {
  const enterStart = 0.50 + index * 0.02
  const enterEnd = enterStart + 0.08

  const cardOpacity = useTransform(scrollProgress, [enterStart, enterEnd, 0.92, 1.0], [0, 1, 1, 0.92])
  const cardY = useTransform(scrollProgress, [enterStart, enterEnd], [30, 0])
  const cardScale = useTransform(scrollProgress, [enterStart, enterEnd], [0.9, 1])
  const cardRotate = useTransform(scrollProgress, [0.50, 0.84], [index % 2 === 0 ? -2.5 : 2.2, index % 2 === 0 ? -1 : 1])

  const rearrangeX = useTransform(
    scrollProgress,
    [0.70, 0.84],
    [card.x, card.x * 0.6]
  )
  const rearrangeY = useTransform(
    scrollProgress,
    [0.70, 0.84],
    [card.y, card.y * 0.7 - 10]
  )

  return (
    <motion.div
      className={`absolute left-1/2 top-1/2 w-48 rounded-xl border px-3 py-2.5 shadow-[0_10px_30px_-12px_rgba(50,45,80,0.55)] backdrop-blur-sm transition-shadow hover:shadow-[0_12px_34px_-10px_rgba(40,37,73,0.65)] dark:shadow-black/30 dark:hover:shadow-black/40 md:w-56 ${card.color}`}
      style={{
        x: rearrangeX,
        y: rearrangeY,
        opacity: cardOpacity,
        translateY: cardY,
        scale: cardScale,
        rotate: cardRotate,
        translateX: '-50%',
        marginTop: '-50%',
      }}
      whileHover={{ scale: 1.04, y: -4 }}
      transition={{ type: 'tween', duration: 0.2 }}
    >
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${SEV_DOT[card.severity]}`} />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-carbon-text-secondary dark:text-ibm-gray-30">
          {card.severity}
        </span>
      </div>
      <p className="mt-1 text-[12px] font-medium leading-snug text-carbon-text dark:text-ibm-gray-10 md:text-[13px]">
        {card.label}
      </p>
    </motion.div>
  )
}

export default function FloatingBoard({ scrollProgress }) {
  const boardOpacity = useTransform(scrollProgress, [0.48, 0.56, 0.92, 1.0], [0, 1, 1, 0.95])
  const boardRotateX = useTransform(scrollProgress, [0.50, 0.70, 0.84], [15, 9, 4])
  const boardRotateY = useTransform(scrollProgress, [0.50, 0.70, 0.84], [-8, -2, -1])
  const boardScale = useTransform(scrollProgress, [0.48, 0.58, 0.84], [0.86, 1, 0.96])
  const boardY = useTransform(scrollProgress, [0.48, 0.58, 0.84], [34, 0, -8])
  const chipOpacity = useTransform(scrollProgress, [0.54, 0.64], [0, 1])

  return (
    <motion.div
      className="absolute inset-0 flex items-center justify-center"
      style={{ opacity: boardOpacity }}
    >
      <motion.div
        className="relative h-80 w-[86%] max-w-2xl rounded-3xl border border-black/[0.05] bg-gradient-to-br from-[#ffffff] via-[#f7f8fd] to-[#eef1f8] shadow-[0_25px_95px_-24px_rgba(43,53,84,0.35)] dark:border-white/[0.06] dark:from-ibm-gray-90/85 dark:via-ibm-gray-100/70 dark:to-ibm-gray-80/65 dark:shadow-[0_16px_64px_-16px_rgba(0,0,0,0.4)] md:h-96"
        style={{
          rotateX: boardRotateX,
          rotateY: boardRotateY,
          scale: boardScale,
          y: boardY,
          transformPerspective: 1200,
        }}
      >
        {/* Board header bar */}
        <div className="flex items-center gap-2 border-b border-black/[0.04] px-5 py-3 dark:border-white/[0.04]">
          <div className="h-2 w-2 rounded-full bg-ibm-blue-50" />
          <span className="text-[10px] font-medium uppercase tracking-widest text-carbon-text-tertiary dark:text-ibm-gray-50">
            Scan results
          </span>
          <div className="ml-auto flex gap-1">
            <div className="h-1.5 w-6 rounded-full bg-ibm-green-40/40 dark:bg-ibm-green-60/30" />
            <div className="h-1.5 w-4 rounded-full bg-ibm-blue-40/40 dark:bg-ibm-blue-60/30" />
          </div>
        </div>
        <motion.div className="absolute -top-8 left-8 flex gap-2" style={{ opacity: chipOpacity }}>
          <div className="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-blue-700 shadow-sm dark:border-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
            Gate: pass
          </div>
          <div className="rounded-lg border border-fuchsia-200 bg-fuchsia-50 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-fuchsia-700 shadow-sm dark:border-fuchsia-800 dark:bg-fuchsia-900/30 dark:text-fuchsia-300">
            AI checked
          </div>
        </motion.div>
        {/* Floating cards */}
        <div className="relative h-full w-full">
          {CARDS.map((card, i) => (
            <TaskCard key={i} card={card} index={i} scrollProgress={scrollProgress} />
          ))}
        </div>
      </motion.div>
    </motion.div>
  )
}
