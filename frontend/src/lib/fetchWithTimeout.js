const DEFAULT_TIMEOUT_MS = 30000

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
    return (
      'Request timed out before the server responded. If the scan is large or uses Gemini/Voyage, try again ' +
      'or set PROMPTSHIELD_SCAN_MODE=fast in backend/.env. Otherwise confirm the API is on port 8000 ' +
      'and the Vite dev server proxies /api.'
    )
  }
  return err?.message || fallback
}
