"""Multi-tenant middleware and helpers — Mongo-backed (v0.4 port).

Every request resolves an org context from the session cookie or API key.
Downstream queries use `get_org_id()` to scope data access.

Orgs in Mongo embed both `members` and `api_keys` arrays directly under each
organization document — matches NoSQL data-locality best practice and lets a
single query authorize a request.
"""
from __future__ import annotations

import hashlib
import secrets
from contextvars import ContextVar
from typing import Any, Optional

from fastapi import HTTPException, Request

import repositories as repos
from auth import SessionUser

_org_id_ctx: ContextVar[Optional[str]] = ContextVar("org_id", default=None)


def get_org_id() -> Optional[str]:
    return _org_id_ctx.get()


def set_org_id(org_id: Optional[Any]) -> None:
    _org_id_ctx.set(str(org_id) if org_id is not None else None)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash)."""
    raw = f"ps_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    key_hash = hash_api_key(raw)
    return raw, prefix, key_hash


def resolve_org_from_api_key(_db_unused: Any, raw_key: str) -> Optional[str]:
    h = hash_api_key(raw_key)
    org = repos.find_org_by_api_key_hash(h)
    return str(org["_id"]) if org else None


def resolve_org_from_user(_db_unused: Any, user: SessionUser) -> Optional[str]:
    """First org membership for a user."""
    from mongo import C, col

    org = col(C.ORGANIZATIONS).find_one({"members.user_id": str(user.id)})
    return str(org["_id"]) if org else None


def get_user_org_role(_db_unused: Any, user_id: Any, org_id: Any) -> Optional[str]:
    org = repos.get_org_by_id(org_id)
    if not org:
        return None
    uid = str(user_id)
    for m in org.get("members") or []:
        if str(m.get("user_id")) == uid:
            return m.get("role")
    return None


def create_org(_db_unused: Any, name: str, slug: str, creator: SessionUser):
    """Create an org with the creator embedded as the first admin member."""
    org = repos.create_org(name=name, slug=slug)
    repos.add_org_member(org["_id"], user_id=str(creator.id), role="admin")
    org = repos.get_org_by_id(org["_id"]) or org
    return org


def require_org_role(*roles: str):
    """Dependency: user must belong to current org with one of the given roles."""
    allowed = set(roles)

    def _dep(request: Request):
        from auth import get_current_user

        user = get_current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        org_id = get_org_id()
        if org_id is None:
            raise HTTPException(status_code=400, detail="No organization context")
        role = get_user_org_role(None, user.id, org_id)
        if role is None or (allowed and role not in allowed):
            raise HTTPException(status_code=403, detail="Insufficient org role")
        return user

    return _dep
