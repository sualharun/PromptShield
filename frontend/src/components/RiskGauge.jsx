import { useEffect, useState } from 'react'

function colorFor(score) {
  if (score <= 30) return '#24a148'
  if (score <= 60) return '#f1c21b'
  if (score <= 85) return '#ff832b'
  return '#da1e28'
}

function labelFor(score) {
  if (score <= 30) return 'Low risk'
  if (score <= 60) return 'Moderate'
  if (score <= 85) return 'High risk'
  return 'Critical'
}

export default function RiskGauge({ score = 0, size = 180 }) {
  const [animated, setAnimated] = useState(0)

  useEffect(() => {
    setAnimated(0)
    const start = performance.now()
    const duration = 900
    let raf
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setAnimated(score * eased)
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [score])

  const stroke = 12
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const dash = (animated / 100) * circumference
  const color = colorFor(score)

  return (
    <div className="relative inline-flex flex-col items-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          className="stroke-ibm-gray-20 dark:stroke-ibm-gray-80"
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeDasharray={`${dash} ${circumference}`}
          style={{ transition: 'stroke 0.3s ease' }}
        />
      </svg>
      <div
        className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center"
      >
        <div
          className="text-[44px] font-light leading-none tabular-nums"
          style={{ color }}
        >
          {Math.round(animated)}
        </div>
        <div className="mt-1 text-[10px] font-medium uppercase tracking-[0.1em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          {labelFor(score)}
        </div>
      </div>
    </div>
  )
}
