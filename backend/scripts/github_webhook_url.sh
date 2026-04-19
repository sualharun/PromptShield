#!/usr/bin/env bash
# Print the GitHub App Webhook URL to paste into GitHub (Developer settings → your App → Webhook).
# Requires ngrok running with its local inspector (default http://127.0.0.1:4040), e.g.:
#   ngrok http 8000
# in another terminal while uvicorn listens on port 8000.

set -euo pipefail

NGROK_API="${NGROK_API:-http://127.0.0.1:4040/api/tunnels}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

if ! curl -fsS "$NGROK_API" -o /dev/null 2>/dev/null; then
  echo "Could not reach ngrok at ${NGROK_API}" >&2
  echo "Start ngrok in another terminal (backend on 8000):" >&2
  echo "  ngrok http 8000" >&2
  exit 1
fi

URL="$(
  curl -fsS "$NGROK_API" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for t in data.get('tunnels', []):
    u = (t.get('public_url') or '').strip()
    if u.startswith('https://'):
        print(u + '/api/github/webhook')
        sys.exit(0)
sys.exit(1)
" || true
)"

if [[ -z "$URL" ]]; then
  echo "No HTTPS tunnel found in ngrok response." >&2
  echo "Open http://127.0.0.1:4040 and confirm a tunnel is up." >&2
  exit 1
fi

echo ""
echo "Paste this into GitHub App → Webhook URL → Save changes:"
echo ""
echo "  $URL"
echo ""
echo "Then: App → Advanced → Recent Deliveries (expect 2xx on pull_request)."
echo ""
