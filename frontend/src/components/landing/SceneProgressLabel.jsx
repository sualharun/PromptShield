import { motion, useMotionValueEvent, useTransform } from 'framer-motion'
import { useState } from 'react'

const LABELS = [
  '001 — Intro',
  '002 — Metal Plane',
  '003 — Task Board',
  '004 — Secure Delivery',
]

export default function SceneProgressLabel({ scrollProgress }) {
  const [labelIndex, setLabelIndex] = useState(0)
  const index = useTransform(scrollProgress, [0, 0.34, 0.50, 0.84, 1], [0, 1, 2, 3, 3])
  const opacity = useTransform(scrollProgress, [0.02, 0.06, 0.92, 1.0], [0, 0.6, 0.6, 0])

  useMotionValueEvent(index, 'change', (value) => {
    const next = Math.max(0, Math.min(3, Math.round(value)))
    setLabelIndex((prev) => (prev === next ? prev : next))
  })

  return (
    <motion.div
      className="absolute bottom-5 left-6 z-10 font-mono text-[10px] tracking-[0.2em] text-carbon-text-tertiary dark:text-ibm-gray-50"
      style={{ opacity }}
    >
      <motion.span key={labelIndex}>{LABELS[labelIndex]}</motion.span>
    </motion.div>
  )
}
