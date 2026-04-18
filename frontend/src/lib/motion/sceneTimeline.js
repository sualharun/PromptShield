/**
 * Centralized phase ranges and easing for the scroll-scrub landing scene.
 * All progress values are 0..1 mapped to total scroll distance.
 */

export const PHASES = {
  intro:      [0.00, 0.18],
  compress:   [0.18, 0.34],
  metalPlane: [0.34, 0.50],
  board:      [0.50, 0.70],
  rotate:     [0.70, 0.84],
  lockup:     [0.84, 1.00],
}

export const SCROLL_HEIGHT = '400vh'

export function phaseProgress(scrollProgress, phase) {
  const [start, end] = PHASES[phase]
  const range = end - start
  if (range === 0) return 0
  return Math.max(0, Math.min(1, (scrollProgress - start) / range))
}

export function rangeMap(value, inMin, inMax, outMin, outMax) {
  const clamped = Math.max(inMin, Math.min(inMax, value))
  return outMin + ((clamped - inMin) / (inMax - inMin)) * (outMax - outMin)
}
