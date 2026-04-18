"""GitHub App auth + thin REST client.

We deliberately keep this small: just the verbs the webhook handler needs.
"""

import base64
import hashlib
import hmac
import logging
import time
from threading import Lock
from typing import Any, Dict, List, Optional

import httpx

try:
    import jwt  # PyJWT
except ImportError:  # pragma: no cover - import guarded for static-only mode
    jwt = None

from config import settings

logger = logging.getLogger("promptshield.github")

GITHUB_API = "https://api.github.com"
USER_AGENT = "PromptShield/0.3"


# ─── Webhook signature verification ──────────────────────────────────────────

def verify_webhook_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = header.split("=", 1)[1]
    return hmac.compare_digest(expected, provided)


# ─── App JWT + installation token cache ──────────────────────────────────────

_token_cache: Dict[int, tuple[str, float]] = {}
_token_lock = Lock()


def sign_app_jwt() -> str:
    """RS256 JWT identifying the App itself. Valid ~9 minutes."""
    if jwt is None:
        raise RuntimeError("PyJWT[crypto] is not installed")
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
        raise RuntimeError("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set")
    now = int(time.time())
    payload = {
        "iat": now - 30,
        "exp": now + 9 * 60,
        "iss": str(settings.GITHUB_APP_ID),
    }
    return jwt.encode(payload, settings.GITHUB_APP_PRIVATE_KEY, algorithm="RS256")


def get_installation_token(installation_id: int) -> str:
    """Exchange the App JWT for an installation token. Cached until ~5min before expiry."""
    with _token_lock:
        cached = _token_cache.get(installation_id)
        if cached and cached[1] - time.time() > 300:
            return cached[0]
    app_jwt = sign_app_jwt()
    r = httpx.post(
        f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
        timeout=10.0,
    )
    r.raise_for_status()
    data = r.json()
    token = data["token"]
    # GitHub returns ISO-8601 expiry; parse via fromisoformat after stripping Z.
    expires_at = data.get("expires_at", "")
    try:
        from datetime import datetime
        expiry_ts = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
    except Exception:
        expiry_ts = time.time() + 3300  # ~55min default
    with _token_lock:
        _token_cache[installation_id] = (token, expiry_ts)
    return token


# ─── Thin REST client ────────────────────────────────────────────────────────


class GitHubClient:
    def __init__(self, token: str, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            base_url=GITHUB_API,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15.0,
            transport=transport,
        )

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._client.close()

    def list_pr_files(self, owner: str, repo: str, number: int) -> List[Dict[str, Any]]:
        files: List[Dict[str, Any]] = []
        page = 1
        while True:
            r = self._client.get(
                f"/repos/{owner}/{repo}/pulls/{number}/files",
                params={"per_page": 100, "page": page},
            )
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
            if page > 10:  # safety: cap PRs at 1000 files
                break
        return files

    def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> Optional[str]:
        r = self._client.get(
            f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref}
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return None  # path is a directory
        if data.get("encoding") != "base64":
            return data.get("content")
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None

    def create_review(
        self,
        owner: str,
        repo: str,
        number: int,
        commit_id: str,
        body: str,
        comments: List[Dict[str, Any]],
        event: str = "COMMENT",
    ) -> Dict[str, Any]:
        r = self._client.post(
            f"/repos/{owner}/{repo}/pulls/{number}/reviews",
            json={
                "commit_id": commit_id,
                "body": body,
                "event": event,
                "comments": comments,
            },
        )
        r.raise_for_status()
        return r.json()

    def create_check_run(
        self, owner: str, repo: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        r = self._client.post(f"/repos/{owner}/{repo}/check-runs", json=payload)
        r.raise_for_status()
        return r.json()

    def update_check_run(
        self, owner: str, repo: str, check_run_id: int, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        r = self._client.patch(
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}", json=payload
        )
        r.raise_for_status()
        return r.json()
