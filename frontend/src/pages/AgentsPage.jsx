import { useMemo, useState } from 'react'
import { ArrowRight, Bot, Trash2 } from 'lucide-react'
import {
  AGENT_PROVIDERS,
  buildAgentActivity,
  normalizeHandle,
  providerMeta,
} from '../lib/agentAccounts.js'

function EmptyState() {
  return (
    <div className="border border-dashed border-carbon-border bg-white px-6 py-10 text-center dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
      <div className="mx-auto flex h-12 w-12 items-center justify-center border border-carbon-border bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
        <Bot className="h-5 w-5 text-ibm-blue-60 dark:text-ibm-blue-30" />
      </div>
      <h2 className="mt-4 text-lg font-medium text-carbon-text dark:text-ibm-gray-10">
        No coding-agent accounts connected
      </h2>
      <p className="mx-auto mt-2 max-w-xl text-[13px] leading-[1.6] text-carbon-text-tertiary dark:text-ibm-gray-40">
        Add Codex, Claude, and Cursor identities with their GitHub handles so PromptShield can
        differentiate their PRs and show which agent actions are being processed.
      </p>
    </div>
  )
}

function ProviderBadge({ provider }) {
  const meta = providerMeta(provider)
  return (
    <span className={`inline-flex items-center gap-2 border px-2.5 py-1 text-[11px] font-medium ${meta.tone}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.accent }} />
      {meta.label}
    </span>
  )
}

export default function AgentsPage({ agentAccounts, onAddAccount, onRemoveAccount, scans = [] }) {
  const [provider, setProvider] = useState('codex')
  const [displayName, setDisplayName] = useState('')
  const [githubHandle, setGithubHandle] = useState('')
  const [repoScope, setRepoScope] = useState('')
  const [error, setError] = useState(null)

  const activity = useMemo(
    () => buildAgentActivity(agentAccounts, scans).slice(0, 8),
    [agentAccounts, scans]
  )

  const submit = (e) => {
    e.preventDefault()
    const normalizedHandle = normalizeHandle(githubHandle)

    if (!normalizedHandle) {
      setError('GitHub handle is required so PR activity can be attributed.')
      return
    }

    const exists = agentAccounts.some(
      (account) =>
        normalizeHandle(account.githubHandle) === normalizedHandle &&
        account.provider === provider
    )
    if (exists) {
      setError('That provider and GitHub handle are already connected.')
      return
    }

    const meta = providerMeta(provider)
    onAddAccount?.({
      id: `${provider}-${Date.now()}`,
      provider,
      displayName: displayName.trim() || `${meta.label} account`,
      githubHandle: normalizedHandle,
      repoScope: repoScope.trim(),
      createdAt: new Date().toISOString(),
    })

    setDisplayName('')
    setGithubHandle('')
    setRepoScope('')
    setError(null)
  }

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      <div className="mb-6">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ibm-blue-70 dark:text-ibm-blue-40">
          Agent directory
        </p>
        <h1 className="mt-2 text-4xl font-light text-carbon-text dark:text-ibm-gray-10">
          Connect coding-agent accounts
        </h1>
        <p className="mt-2 max-w-3xl text-[14px] leading-[1.65] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Register Codex, Claude, and Cursor accounts with their GitHub handles. PromptShield
          will use those mappings to differentiate processed PRs and agent actions across repos.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[420px,1fr]">
        <section className="border border-carbon-border bg-white p-6 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="mb-5">
            <h2 className="text-[12px] font-semibold uppercase tracking-[0.12em] text-carbon-text-secondary dark:text-ibm-gray-30">
              Add account
            </h2>
            <p className="mt-2 text-[13px] leading-[1.6] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Map each coding-agent account to the GitHub identity that opens or updates pull
              requests.
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Provider
              </span>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="mt-1 w-full border border-carbon-border bg-carbon-bg px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
              >
                {AGENT_PROVIDERS.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Display name
              </span>
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Security review bot"
                className="mt-1 w-full border border-carbon-border bg-carbon-bg px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
              />
            </label>

            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
                GitHub handle
              </span>
              <input
                required
                value={githubHandle}
                onChange={(e) => setGithubHandle(e.target.value)}
                placeholder="@agent-user"
                className="mt-1 w-full border border-carbon-border bg-carbon-bg px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
              />
            </label>

            <label className="block">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Optional repo scope
              </span>
              <input
                value={repoScope}
                onChange={(e) => setRepoScope(e.target.value)}
                placeholder="acme/core-platform"
                className="mt-1 w-full border border-carbon-border bg-carbon-bg px-3 py-2 text-sm text-carbon-text focus:border-ibm-blue-60 focus:outline-none dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10"
              />
            </label>

            {error && (
              <div className="border border-ibm-red-60 bg-[#fff1f1] px-3 py-2 text-[12px] text-ibm-red-60 dark:bg-ibm-red-60/10">
                {error}
              </div>
            )}

            <button
              type="submit"
              className="inline-flex w-full items-center justify-center gap-2 border border-ibm-blue-60 bg-ibm-blue-60 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-ibm-blue-70"
            >
              Add agent account
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>
        </section>

        <div className="space-y-6">
          {agentAccounts.length === 0 ? (
            <EmptyState />
          ) : (
            <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {agentAccounts.map((account) => {
                const meta = providerMeta(account.provider)
                const processedCount = activity.filter((entry) => entry.account.id === account.id).length
                return (
                  <article
                    key={account.id}
                    className="border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <ProviderBadge provider={account.provider} />
                        <div className="mt-3 text-lg font-medium text-carbon-text dark:text-ibm-gray-10">
                          {account.displayName}
                        </div>
                        <div className="mt-1 font-mono text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
                          @{normalizeHandle(account.githubHandle)}
                        </div>
                      </div>
                      <button
                        onClick={() => onRemoveAccount?.(account.id)}
                        className="inline-flex h-8 w-8 items-center justify-center border border-carbon-border text-carbon-text-secondary transition-colors hover:border-ibm-red-60 hover:text-ibm-red-60 dark:border-ibm-gray-80 dark:text-ibm-gray-40"
                        aria-label={`Remove ${account.displayName}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                    <p className="mt-4 text-[13px] leading-[1.6] text-carbon-text-tertiary dark:text-ibm-gray-40">
                      {meta.description}
                    </p>
                    <div className="mt-5 grid grid-cols-2 gap-3 border-t border-carbon-border pt-4 dark:border-ibm-gray-80">
                      <div>
                        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                          Processed PRs
                        </div>
                        <div className="mt-1 text-2xl font-light text-carbon-text dark:text-ibm-gray-10">
                          {processedCount}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                          Scope
                        </div>
                        <div className="mt-1 text-[12px] leading-[1.5] text-carbon-text-secondary dark:text-ibm-gray-30">
                          {account.repoScope || 'All repos'}
                        </div>
                      </div>
                    </div>
                  </article>
                )
              })}
            </section>
          )}

          <section className="border border-carbon-border bg-white p-5 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-carbon-text-secondary dark:text-ibm-gray-30">
                Processed agent actions
              </h2>
              <span className="text-[12px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Derived from recent PR scans
              </span>
            </div>
            {!activity.length ? (
              <p className="text-[13px] leading-[1.6] text-carbon-text-tertiary dark:text-ibm-gray-40">
                Once connected accounts match recent PR authors, PromptShield will show which
                provider generated the work and whether the downstream action was cleared or
                held by policy.
              </p>
            ) : (
              <div className="space-y-3">
                {activity.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-start justify-between gap-4 border border-carbon-border bg-carbon-layer px-4 py-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <ProviderBadge provider={entry.account.provider} />
                        <span className="text-[12px] font-medium text-carbon-text dark:text-ibm-gray-10">
                          {entry.account.displayName}
                        </span>
                      </div>
                      <div className="mt-2 text-[13px] leading-[1.55] text-carbon-text dark:text-ibm-gray-10">
                        PR #{entry.scan.pr_number ?? '—'} in {entry.scan.repo_full_name || 'unknown repo'}
                      </div>
                      <div className="mt-1 text-[12px] leading-[1.55] text-carbon-text-tertiary dark:text-ibm-gray-40">
                        {entry.summary}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-carbon-text-tertiary dark:text-ibm-gray-40">
                        Phase
                      </div>
                      <div className="mt-1 text-[12px] font-medium text-ibm-blue-70 dark:text-ibm-blue-30">
                        {entry.phase}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  )
}
