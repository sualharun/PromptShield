"""Authentication primitives: bcrypt hashing, signed-cookie sessions, role gates.

Design notes:
- Sessions are signed JSON payloads in a cookie (`itsdangerous`), not a server-side
  table. Keeps the schema small and avoids a sessions-table migration.
- Roles are `admin` | `pm` | `viewer`. Read endpoints stay public for the demo;
  `require_role(...)` only gates the PM view and future write operations.
"""

import json
from typing import Iterable, Optional

import bcrypt
from fastapi import Cookie, Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from config import settings
from database import User, get_db


SESSION_COOKIE_NAME = "promptshield_session"
_SESSION_SALT = "promptshield-session-v1"


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


def create_session_token(user: User) -> str:
    payload = {"uid": user.id, "email": user.email, "role": user.role}
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
    db: Session = Depends(get_db),
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> Optional[User]:
    """Returns the current user or None. Never raises — use require_role for gates."""
    token = session
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    payload = _decode_session(token) if token else None
    if not payload:
        return None
    user = db.query(User).filter(User.id == payload.get("uid")).first()
    return user


def require_role(*roles: str):
    """FastAPI dependency factory. Returns the user if their role is allowed."""
    allowed = set(roles)

    def _dep(user: Optional[User] = Depends(get_current_user)) -> User:
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        if allowed and user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _dep


def bootstrap_admin_if_needed(db: Session) -> None:
    """Create a single admin user from env on first startup when the table is empty."""
    email = (settings.BOOTSTRAP_ADMIN_EMAIL or "").strip().lower()
    password = settings.BOOTSTRAP_ADMIN_PASSWORD or ""
    if not email or not password:
        return
    if db.query(User).count() > 0:
        return
    db.add(
        User(
            email=email,
            name=settings.BOOTSTRAP_ADMIN_NAME or "Admin",
            password_hash=hash_password(password),
            role="admin",
        )
    )
    db.commit()
