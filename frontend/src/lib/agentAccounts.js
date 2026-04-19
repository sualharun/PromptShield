import { fetchWithTimeout } from './fetchWithTimeout.js'

const STORAGE_KEY = 'promptshield_agent_accounts_v1'

export const AGENT_PROVIDERS = [
  {
    id: 'codex',
    label: 'Codex',
    accent: '#0f62fe',
    tone: 'bg-[#0f62fe]/10 text-[#78a9ff] border-[#0f62fe]/30',
    description: 'OpenAI coding-agent activity and downstream patch execution.',
  },
  {
    id: 'claude',
    label: 'Claude',
    accent: '#8a3ffc',
    tone: 'bg-[#8a3ffc]/10 text-[#c7a2ff] border-[#8a3ffc]/30',
    description: 'Anthropic agent tasks, semantic review, and tool decisions.',
  },
  {
    id: 'cursor',
    label: 'Cursor',
    accent: '#24a148',
    tone: 'bg-[#24a148]/10 text-[#8de0a8] border-[#24a148]/30',
    description: 'IDE-driven agent requests, repo handoffs, and patch generation.',
  },
]

function safeLocalStorage() {
  try {
    return window.localStorage
  } catch {
    return null
  }
}

export function loadAgentAccounts() {
  const storage = safeLocalStorage()
  if (!storage) return []
  try {
    const raw = storage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function saveAgentAccounts(accounts) {
  const storage = safeLocalStorage()
  if (!storage) return
  storage.setItem(STORAGE_KEY, JSON.stringify(accounts))
}

function fromApiAccount(account) {
  return {
    id: account.id,
    provider: account.provider,
    displayName: account.displayName,
    githubHandle: account.githubHandle,
    repoScope: account.repoScope || '',
    createdAt: account.createdAt,
  }
}

export async function fetchAgentAccountsApi() {
  const response = await fetchWithTimeout('/api/agents/accounts')
  if (!response.ok) {
    throw new Error(`Failed to load agent accounts (${response.status})`)
  }
  const data = await response.json()
  return Array.isArray(data) ? data.map(fromApiAccount) : []
}

export async function createAgentAccountApi(account) {
  const response = await fetchWithTimeout('/api/agents/accounts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      provider: account.provider,
      displayName: account.displayName,
      githubHandle: account.githubHandle,
      repoScope: account.repoScope || '',
    }),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw new Error(detail.detail || `Failed to create agent account (${response.status})`)
  }
  return fromApiAccount(await response.json())
}

export async function deleteAgentAccountApi(accountId) {
  const response = await fetchWithTimeout(`/api/agents/accounts/${encodeURIComponent(accountId)}`, {
    method: 'DELETE',
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw new Error(detail.detail || `Failed to remove account (${response.status})`)
  }
}

export function providerMeta(providerId) {
  return (
    AGENT_PROVIDERS.find((provider) => provider.id === providerId) || AGENT_PROVIDERS[0]
  )
}

export function normalizeHandle(value) {
  return String(value || '')
    .trim()
    .replace(/^@+/, '')
    .toLowerCase()
}

export function matchAgentAccount(accounts, scan) {
  const author = normalizeHandle(scan?.author_login)
  const repo = String(scan?.repo_full_name || '').trim().toLowerCase()
  if (!author) return null

  return (
    accounts.find((account) => {
      const handleMatches = normalizeHandle(account.githubHandle) === author
      if (!handleMatches) return false

      const scopedRepo = String(account.repoScope || '').trim().toLowerCase()
      if (!scopedRepo) return true
      return repo.includes(scopedRepo)
    }) || null
  )
}

export function buildAgentActivity(accounts, scans = []) {
  return scans
    .map((scan) => {
      const account = matchAgentAccount(accounts, scan)
      if (!account) return null

      return {
        id: `${account.id}-${scan.id}`,
        account,
        scan,
        phase: scan.risk_score >= 70 ? 'policy gate' : 'review completed',
        summary:
          scan.risk_score >= 70
            ? 'PR blocked and downstream actions held for review.'
            : 'PR scanned and agent handoff cleared for continuation.',
      }
    })
    .filter(Boolean)
}
