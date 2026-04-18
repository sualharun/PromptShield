import { useState } from 'react'
import { useAuth } from '../auth/AuthContext.jsx'

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

  return (
    <div className="mx-auto w-full max-w-md px-6 py-16">
      <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
        Sign in
      </p>
      <h1 className="mt-2 font-light text-3xl text-carbon-text dark:text-ibm-gray-10">
        PromptShield
      </h1>
      <p className="mt-2 text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
        Sign in with the admin account provisioned for your org. Read-only demo
        views remain available without sign-in.
      </p>

      <form onSubmit={submit} className="mt-6 space-y-4">
        <label className="block">
          <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Email
          </span>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full border border-carbon-border bg-white px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
            autoComplete="email"
          />
        </label>
        <label className="block">
          <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
            Password
          </span>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full border border-carbon-border bg-white px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
            autoComplete="current-password"
          />
        </label>
        {error && (
          <div className="border border-ibm-red-60 bg-[#fff1f1] px-3 py-2 text-[12px] text-ibm-red-60 dark:bg-ibm-red-60/10">
            {error}
          </div>
        )}
        <button
          type="submit"
          disabled={submitting}
          className="w-full border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70 disabled:opacity-60"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
