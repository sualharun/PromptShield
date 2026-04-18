import { useAuth } from '../auth/AuthContext.jsx'

export default function AuthBadge({ onSignIn }) {
  const { user, logout, loading } = useAuth()

  if (loading) {
    return (
      <span className="text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
        …
      </span>
    )
  }

  if (!user) {
    return (
      <button
        onClick={onSignIn}
        className="text-[11px] font-medium uppercase tracking-[0.08em] text-ibm-blue-60 hover:underline dark:text-ibm-blue-40"
      >
        Sign in
      </button>
    )
  }

  return (
    <span className="flex items-center gap-2 text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
      <span className="font-medium">{user.name}</span>
      <span className="border border-carbon-border px-1.5 py-0.5 font-mono uppercase tracking-wider text-[10px] dark:border-ibm-gray-80">
        {user.role}
      </span>
      <button
        onClick={logout}
        className="text-[11px] text-carbon-text-tertiary hover:underline dark:text-ibm-gray-40"
      >
        Sign out
      </button>
    </span>
  )
}
