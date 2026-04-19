"""Authentication primitives: bcrypt hashing, signed-cookie sessions, role gates.

v0.4: Backed by MongoDB Atlas (`users` collection).
The public surface (`get_current_user`, `require_role`, `create_session_token`,
`hash_password`, `verify_password`, `bootstrap_admin_if_needed`) is unchanged
so every dependent router keeps working without edits.

We expose a `SessionUser` dataclass with `.id`, `.email`, `.name`, `.role` so
existing handlers keep working unchanged.

Sessions are still signed JSON in a cookie via `itsdangerous` — no server-side
session table. Roles are `admin` | `pm` | `viewer`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import bcrypt
from fastapi import Cookie, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import repositories as repos
from config import settings


SESSION_COOKIE_NAME = "promptshield_session"
_SESSION_SALT = "promptshield-session-v1"


@dataclass
class SessionUser:
    """In-memory user view backed by a Mongo user document.

    `id` is the string ObjectId. Handlers read `user.id`, `user.email`, etc.
    """

    id: str
    email: str
    name: str
    role: str

    @classmethod
    def from_doc(cls, doc: dict) -> "SessionUser":
        return cls(
            id=str(doc.get("_id") or doc.get("id") or ""),
            email=doc.get("email") or "",
            name=doc.get("name") or "",
            role=doc.get("role") or "viewer",
        )


# Re-export under the legacy name `User` so `from auth import User` keeps working.
User = SessionUser


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.SESSION_SECRET, salt=_SESSION_SALT)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_session_token(user: Any) -> str:
    """Accepts a SessionUser or a Mongo user dict."""
    if isinstance(user, dict):
        uid = str(user.get("_id") or user.get("id") or "")
        email = user.get("email") or ""
        role = user.get("role") or "viewer"
    else:
        uid = str(getattr(user, "id", ""))
        email = getattr(user, "email", "")
        role = getattr(user, "role", "viewer")
    payload = {"uid": uid, "email": email, "role": role}
    return _serializer().dumps(payload)


def _decode_session(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        return _serializer().loads(token, max_age=settings.SESSION_MAX_AGE_SECONDS)
    except SignatureExpired:
        return None
    except BadSignature:
        return None


def get_current_user(
    request: Request,
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> Optional[SessionUser]:
    """Returns the current SessionUser or None. Never raises — use require_role for gates.

    `db` parameter removed (legacy). Callers that pass it via
    `Depends(get_current_user)` are unaffected because FastAPI resolves
    dependencies by signature, not by call site.
    """
    token = session
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    payload = _decode_session(token) if token else None
    if not payload:
        return None
    uid = payload.get("uid")
    if not uid:
        return None
    doc = repos.get_user_by_id(uid)
    if not doc:
        return None
    return SessionUser.from_doc(doc)


def require_role(*roles: str):
    """FastAPI dependency factory. Returns the user if their role is allowed."""
    allowed = set(roles)

    from fastapi import Depends

    def _dep(user: Optional[SessionUser] = Depends(get_current_user)) -> SessionUser:
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        if allowed and user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _dep


def bootstrap_admin_if_needed(_db_unused: Any = None) -> None:
    """Create a single admin user from env on first startup when the table is empty.

    Signature accepts a positional argument so existing callers (`bootstrap_admin_if_needed(db)`)
    don't break — the SQL session is now ignored.
    """
    email = (settings.BOOTSTRAP_ADMIN_EMAIL or "").strip().lower()
    password = settings.BOOTSTRAP_ADMIN_PASSWORD or ""
    if not email or not password:
        return
    if repos.count_users() > 0:
        return
    repos.insert_user(
        {
            "email": email,
            "name": settings.BOOTSTRAP_ADMIN_NAME or "Admin",
            "password_hash": hash_password(password),
            "role": "admin",
        }
    )
