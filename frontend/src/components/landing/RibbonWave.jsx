import { motion, useTransform } from 'framer-motion'

const SEGMENTS = Array.from({ length: 24 }, (_, i) => ({
  id: i,
  tone:
    i % 4 === 0
      ? 'from-[#fbc5e8] to-[#d89cff]'
      : i % 4 === 1
        ? 'from-[#b9e4ff] to-[#7ab8ff]'
        : i % 4 === 2
          ? 'from-[#ffb7c6] to-[#ef8ea8]'
          : 'from-[#c4b5fd] to-[#8fb2ff]',
}))

export default function RibbonWave({ scrollProgress }) {
  const ribbonY = useTransform(scrollProgress, [0, 0.18, 0.34], [-8, -18, -220])
  const ribbonScale = useTransform(scrollProgress, [0, 0.18, 0.34], [1, 1, 0.46])
  const ribbonOpacity = useTransform(scrollProgress, [0, 0.18, 0.30, 0.34], [1, 1, 0.7, 0])
  const ribbonRotate = useTransform(scrollProgress, [0, 0.18, 0.34], [0, -1.5, -5])

  return (
    <motion.div
      className="pointer-events-none relative h-28 w-full overflow-visible md:h-32"
      style={{ y: ribbonY, scale: ribbonScale, opacity: ribbonOpacity, rotate: ribbonRotate }}
    >
      <div className="absolute left-0 right-0 top-1/2 h-px bg-black/[0.04] dark:bg-white/[0.05]" />
      {SEGMENTS.map((segment, i) => (
        <motion.div
          key={segment.id}
          className={`absolute top-1/2 h-[88px] w-8 rounded-[10px] bg-gradient-to-b ${segment.tone} shadow-[0_8px_26px_-10px_rgba(95,70,150,0.55)] md:h-[108px] md:w-9`}
          style={{
            left: `calc(${(i / (SEGMENTS.length - 1)) * 100}% - 16px)`,
            x: useTransform(scrollProgress, [0, 0.20], [Math.sin(i * 0.65) * 10, Math.sin(i * 0.42) * 4]),
            y: useTransform(scrollProgress, [0, 0.16, 0.24], [Math.sin(i * 0.4) * 22 - 28, Math.sin(i * 0.55) * 16 - 26, -24]),
            rotate: useTransform(scrollProgress, [0, 0.18, 0.34], [Math.sin(i * 0.35) * 24, Math.sin(i * 0.22) * 16, Math.sin(i * 0.1) * 6]),
          }}
        />
      ))}
    </motion.div>
  )
}
