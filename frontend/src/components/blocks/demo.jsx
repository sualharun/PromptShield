import { HeroSection } from '../ui/hero-section-1.jsx'

export function Demo({ onDashboard, onScan }) {
  return <HeroSection onPrimary={onDashboard} onSecondary={onScan} />
}
