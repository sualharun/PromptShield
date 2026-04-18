import { useCallback, useEffect, useState } from 'react'

const STORAGE_KEY = 'promptshield_theme'

function readInitial() {
  if (typeof document === 'undefined') return 'dark'
  const attr = document.documentElement.getAttribute('data-theme')
  if (attr === 'light' || attr === 'dark') return attr
  return document.documentElement.classList.contains('dark') ? 'dark' : 'dark'
}

function applyTheme(theme) {
  const root = document.documentElement
  root.classList.toggle('dark', theme === 'dark')
  root.setAttribute('data-theme', theme)
}

export function useTheme() {
  const [theme, setTheme] = useState(readInitial)

  useEffect(() => {
    applyTheme(theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const toggle = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  }, [])

  return { theme, toggle }
}

function SunIcon() {
  return (
    <svg
      aria-hidden
      viewBox="0 0 20 20"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
    >
      <circle cx="10" cy="10" r="3.2" />
      <path d="M10 2.5v1.8M10 15.7v1.8M3.5 10H1.7M18.3 10h-1.8M5.2 5.2 3.9 3.9M16.1 16.1l-1.3-1.3M5.2 14.8 3.9 16.1M16.1 3.9l-1.3 1.3" />
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg
      aria-hidden
      viewBox="0 0 20 20"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M16 11.5A6.5 6.5 0 0 1 8.5 4c0-.6.08-1.2.23-1.76A7 7 0 1 0 17.76 11.27c-.56.15-1.16.23-1.76.23Z" />
    </svg>
  )
}

export default function ThemeToggle() {
  const { theme, toggle } = useTheme()
  const nextLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={nextLabel}
      title={nextLabel}
      className="inline-flex h-8 w-8 items-center justify-center text-carbon-text-secondary transition-colors hover:bg-carbon-layer hover:text-carbon-text dark:text-ibm-gray-30 dark:hover:bg-ibm-gray-90 dark:hover:text-white"
    >
      {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
    </button>
  )
}
