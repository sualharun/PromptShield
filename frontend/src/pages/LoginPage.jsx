import { useState } from 'react'
import { ArrowRight, Lock, Mail } from 'lucide-react'
import { useAuth } from '../auth/AuthContext.jsx'

function GitHubMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className="h-4 w-4 fill-current">
      <path d="M12 2C6.48 2 2 6.59 2 12.24c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49 0-.24-.01-1.04-.01-1.89-2.78.62-3.37-1.21-3.37-1.21-.46-1.2-1.11-1.51-1.11-1.51-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.9 1.57 2.36 1.12 2.94.86.09-.67.35-1.12.63-1.38-2.22-.26-4.55-1.14-4.55-5.08 0-1.12.39-2.04 1.03-2.76-.1-.26-.45-1.31.1-2.73 0 0 .84-.28 2.75 1.05A9.3 9.3 0 0 1 12 6.84c.85 0 1.7.12 2.5.37 1.9-1.34 2.74-1.05 2.74-1.05.55 1.42.2 2.47.1 2.73.64.72 1.03 1.64 1.03 2.76 0 3.95-2.34 4.82-4.57 5.07.36.32.68.95.68 1.92 0 1.39-.01 2.5-.01 2.84 0 .27.18.59.69.49A10.27 10.27 0 0 0 22 12.24C22 6.59 17.52 2 12 2Z" />
    </svg>
  )
}

function GoogleMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className="h-4 w-4">
      <path
        fill="#4285F4"
        d="M21.81 12.23c0-.72-.06-1.25-.19-1.8H12.2v3.56h5.53c-.11.89-.69 2.23-1.97 3.13l-.02.12 2.85 2.16.2.02c1.88-1.7 3.02-4.2 3.02-7.19Z"
      />
      <path
        fill="#34A853"
        d="M12.2 21.9c2.71 0 4.99-.88 6.65-2.4l-3.17-2.3c-.85.58-1.99.98-3.48.98-2.65 0-4.89-1.7-5.69-4.05l-.11.01-2.96 2.24-.04.1c1.65 3.19 5.03 5.42 8.8 5.42Z"
      />
      <path
        fill="#FBBC05"
        d="M6.51 14.13a5.74 5.74 0 0 1-.34-1.93c0-.67.12-1.3.32-1.93l-.01-.13-3-.28-.1.05A9.49 9.49 0 0 0 2.35 12.2c0 1.52.37 2.95 1.03 4.27l3.13-2.34Z"
      />
      <path
        fill="#EB4335"
        d="M12.2 6.23c1.88 0 3.15.79 3.88 1.45l2.83-2.7C17.18 3.42 14.9 2.5 12.2 2.5c-3.77 0-7.15 2.23-8.8 5.42l3.11 2.3c.82-2.35 3.06-3.99 5.69-3.99Z"
      />
    </svg>
  )
}

function SSOButton({ children, icon, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="terminal-soft flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:border-[#78a9ff]/40 hover:bg-[#09111b]"
    >
      <span className="flex items-center gap-3 text-[13px] text-[#eef5ff]">
        {icon}
        <span>{children}</span>
      </span>
      <ArrowRight className="h-4 w-4 text-[#78a9ff]" />
    </button>
  )
}

export default function LoginPage({ onLoggedIn }) {
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [info, setInfo] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    setInfo(null)
    try {
      await login(email.trim().toLowerCase(), password)
      if (onLoggedIn) onLoggedIn()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  const showSSOMessage = (provider) => {
    setError(null)
    setInfo(`${provider} sign-in is not wired on the backend yet. Email and password work today via /api/auth/login.`)
  }

  return (
    <div className="min-h-full bg-[#020406] px-6 py-10 sm:px-10 lg:px-12">
      <div className="mx-auto w-full max-w-[560px]">
        <section className="terminal-panel px-6 py-6 sm:px-8 sm:py-8">
          <div className="terminal-label text-[10px] font-semibold">sign in</div>
          <h2 className="mt-4 terminal-mono text-[30px] font-semibold tracking-[-0.05em] text-[#eef5ff]">
            Choose an auth method
          </h2>
          <p className="mt-3 text-[14px] leading-[1.6] text-[#8eaad2]">
            Social providers are shown here for the login surface. Native email/password is the
            active path in this build.
          </p>

          <div className="mt-6 space-y-3">
            <SSOButton icon={<GitHubMark />} onClick={() => showSSOMessage('GitHub')}>
              Continue with GitHub
            </SSOButton>
            <SSOButton icon={<GoogleMark />} onClick={() => showSSOMessage('Google')}>
              Continue with Google
            </SSOButton>
          </div>

          <div className="my-6 flex items-center gap-3">
            <span className="h-px flex-1 bg-white/10" />
            <span className="terminal-label text-[10px] font-semibold text-[#5f7eaf]">or use email</span>
            <span className="h-px flex-1 bg-white/10" />
          </div>

          <form onSubmit={submit} className="space-y-4">
            <label className="block">
              <span className="terminal-label text-[10px] font-semibold">email</span>
              <div className="app-input mt-2 flex items-center gap-3 px-3 py-3">
                <Mail className="h-4 w-4 text-[#78a9ff]" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-transparent text-sm text-[#eef5ff] outline-none placeholder:text-[#5f7eaf]"
                  autoComplete="email"
                  placeholder="admin@company.com"
                />
              </div>
            </label>

            <label className="block">
              <span className="terminal-label text-[10px] font-semibold">password</span>
              <div className="app-input mt-2 flex items-center gap-3 px-3 py-3">
                <Lock className="h-4 w-4 text-[#78a9ff]" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-transparent text-sm text-[#eef5ff] outline-none placeholder:text-[#5f7eaf]"
                  autoComplete="current-password"
                  placeholder="Enter your password"
                />
              </div>
            </label>

            {info && (
              <div className="border border-[#2b5fb8] bg-[#071221] px-3 py-3 text-[12px] leading-[1.55] text-[#9ec2ff]">
                {info}
              </div>
            )}

            {error && (
              <div className="border border-[#a94b5a] bg-[#1b0c10] px-3 py-3 text-[12px] leading-[1.55] text-[#ffbac6]">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="landing-ibm-button flex w-full items-center justify-center gap-2 px-4 py-3 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60"
            >
              <span>{submitting ? 'Signing in…' : 'Sign in with email'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          <div className="mt-6 border-t border-white/8 pt-4 text-[12px] leading-[1.6] text-[#6f8dbd]">
            Current backend auth routes in this repo:
            <span className="ml-2 terminal-mono text-[#aac3e8]">POST /api/auth/login</span>
            <span className="mx-2 text-white/24">·</span>
            <span className="terminal-mono text-[#aac3e8]">GET /api/auth/me</span>
          </div>
        </section>
      </div>
    </div>
  )
}
