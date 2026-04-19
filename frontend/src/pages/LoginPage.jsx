import { useState } from 'react'
import { ArrowRight, GitBranch, Globe, LockKeyhole } from 'lucide-react'
import { useAuth } from '../auth/AuthContext.jsx'

const OAUTH_UNAVAILABLE =
  'GitHub and Google sign-in are not configured in the backend yet. This repo currently supports email and password only.'

export default function LoginPage({ onLoggedIn }) {
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await login(email.trim().toLowerCase(), password)
      if (onLoggedIn) onLoggedIn()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  const showOAuthUnavailable = () => {
    setError(OAUTH_UNAVAILABLE)
  }

  return (
    <div className="min-h-full bg-[#f3f1ea] px-6 py-16">
      <div className="mx-auto max-w-[560px]">
        <div className="border border-[#de715d]/35 bg-white px-8 py-10 shadow-[0_24px_70px_rgba(22,33,62,0.08)] lg:px-10 lg:py-12">
          <div className="mx-auto flex h-11 w-11 items-center justify-center border border-[#de715d]/35 bg-[#f7f5ef] text-[#16213e]">
            <LockKeyhole className="h-5 w-5" />
          </div>

          <p className="mt-5 text-center text-[11px] font-semibold uppercase tracking-[0.16em] text-[#58532a]">
            Sign in
          </p>
          <h1 className="mt-2 text-center text-[32px] font-light tracking-[-0.04em] text-[#16213e]">
            PromptShield
          </h1>
          <p className="mx-auto mt-4 max-w-[36ch] text-center text-[14px] leading-7 text-[#4b5876]">
            Sign in to access the dashboard, PR scan history, and policy workspace.
          </p>

          <div className="mt-8 grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={showOAuthUnavailable}
              className="inline-flex items-center justify-center gap-2 border border-[#de715d]/32 bg-[#f7f5ef] px-4 py-3 text-sm font-medium text-[#16213e] transition hover:border-[#de715d]"
            >
              <GitBranch className="h-4 w-4" />
              Continue with GitHub
            </button>
            <button
              type="button"
              onClick={showOAuthUnavailable}
              className="inline-flex items-center justify-center gap-2 border border-[#de715d]/32 bg-[#f7f5ef] px-4 py-3 text-sm font-medium text-[#16213e] transition hover:border-[#de715d]"
            >
              <Globe className="h-4 w-4" />
              Continue with Google
            </button>
          </div>

          <div className="mt-6 flex items-center gap-4">
            <div className="h-px flex-1 bg-[#de715d]/18" />
            <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#58532a]">
              Email
            </span>
            <div className="h-px flex-1 bg-[#de715d]/18" />
          </div>

          <form onSubmit={submit} className="mt-6 space-y-5">
            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.1em] text-[#58532a]">
                Email
              </span>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                className="mt-2 w-full border border-[#de715d]/28 bg-white px-4 py-3 text-sm text-[#16213e] focus:border-[#de715d] focus:outline-none"
              />
            </label>

            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.1em] text-[#58532a]">
                Password
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="mt-2 w-full border border-[#de715d]/28 bg-white px-4 py-3 text-sm text-[#16213e] focus:border-[#de715d] focus:outline-none"
              />
            </label>

            {error && (
              <div className="border border-[#de715d]/45 bg-[#fff1ec] px-4 py-3 text-[12px] leading-6 text-[#8f3c2d]">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="inline-flex w-full items-center justify-center gap-2 border border-[#de715d] bg-[#de715d] px-5 py-3 text-sm font-medium text-white transition hover:bg-[#cb624f] disabled:opacity-60"
            >
              {submitting ? 'Signing in…' : 'Sign in'}
              {!submitting && <ArrowRight className="h-4 w-4" />}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
