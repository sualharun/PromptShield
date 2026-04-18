import { motion, useTransform } from 'framer-motion'

export default function MetalPlane({ scrollProgress }) {
  const planeOpacity = useTransform(scrollProgress, [0.30, 0.38, 0.50, 0.56], [0, 1, 1, 0])
  const planeScale = useTransform(scrollProgress, [0.30, 0.42], [0.84, 1.02])
  const planeRotateX = useTransform(scrollProgress, [0.34, 0.50], [19, 6])
  const planeRotateY = useTransform(scrollProgress, [0.34, 0.50], [-10, -2])
  const planeY = useTransform(scrollProgress, [0.30, 0.50], [42, 0])

  return (
    <motion.div
      className="absolute inset-0 flex items-center justify-center"
      style={{ opacity: planeOpacity }}
    >
      {/* Dot grid background */}
      <div
        className="absolute inset-0 opacity-[0.14] dark:opacity-[0.1]"
        style={{
          backgroundImage: 'radial-gradient(circle, currentColor 1px, transparent 1px)',
          backgroundSize: '20px 20px',
        }}
      />
      <div className="absolute inset-0 bg-gradient-to-b from-white/50 to-transparent dark:from-white/[0.03]" />
      {/* Metal sheet */}
      <motion.div
        className="relative h-64 w-[80%] max-w-xl overflow-hidden rounded-2xl border border-white/60 bg-gradient-to-br from-white/95 via-[#f7f8fb]/92 to-[#ebeef5]/90 shadow-[0_24px_84px_-28px_rgba(43,47,62,0.35)] backdrop-blur-md dark:border-white/12 dark:from-ibm-gray-80/70 dark:via-ibm-gray-90/45 dark:to-ibm-gray-100/70 dark:shadow-[0_22px_78px_-24px_rgba(0,0,0,0.55)] md:h-72"
        style={{
          scale: planeScale,
          rotateX: planeRotateX,
          rotateY: planeRotateY,
          y: planeY,
          transformPerspective: 1200,
        }}
      >
        <div className="absolute -left-10 top-0 h-20 w-[120%] -rotate-[6deg] bg-white/55 blur-xl dark:bg-white/[0.06]" />
        <div className="absolute inset-0 bg-gradient-to-br from-white/45 via-transparent to-black/[0.04] dark:from-white/[0.05] dark:to-black/[0.2]" />
        <div className="absolute inset-5 rounded-xl border border-black/[0.06] dark:border-white/[0.08]" />
        <div className="absolute bottom-4 left-4 right-4 flex gap-2">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="h-1 flex-1 rounded-full bg-gradient-to-r from-ibm-blue-30/35 to-ibm-purple-30/35 dark:from-ibm-blue-60/30 dark:to-ibm-purple-60/30"
            />
          ))}
        </div>
      </motion.div>
    </motion.div>
  )
}
