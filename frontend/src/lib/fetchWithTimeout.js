const DEFAULT_TIMEOUT_MS = 8000

// Prevent indefinite pending fetches when backend/proxy is unavailable.
export async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

export function asNetworkErrorMessage(err, fallback = 'Request failed') {
  if (err?.name === 'AbortError') {
    return 'Request timed out. Check backend server and try again.'
  }
  return err?.message || fallback
}
