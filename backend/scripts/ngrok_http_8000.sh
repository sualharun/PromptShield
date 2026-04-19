#!/usr/bin/env bash
# Forward public HTTPS → local FastAPI (default port 8000).
# Run uvicorn first in another terminal, then run this script.
#
# After ngrok shows "started", run in a third terminal:
#   ./backend/scripts/github_webhook_url.sh
# Copy the printed URL into your GitHub App webhook settings.

set -euo pipefail
PORT="${1:-8000}"

if ! command -v ngrok >/dev/null 2>&1; then
  echo "ngrok not found. Install: https://ngrok.com/download" >&2
  echo "Then run once: ngrok config add-authtoken <token>  (from ngrok dashboard)" >&2
  exit 1
fi

echo "Forwarding https → http://127.0.0.1:${PORT}"
echo "Keep this terminal open. In another terminal run: ./backend/scripts/github_webhook_url.sh"
echo ""
exec ngrok http "$PORT"
