"""Multi-tenant middleware and helpers.

Every request resolves an org context from the session cookie or API key.
Downstream queries use `get_org_id()` to scope data access.
"""

import hashlib
import secrets
from contextvars import ContextVar
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import User, get_db
from models import ApiKey, OrgMember, Organization

_org_id_ctx: ContextVar[Optional[int]] = ContextVar("org_id", default=None)


def get_org_id() -> Optional[int]:
    return _org_id_ctx.get()


def set_org_id(org_id: Optional[int]) -> None:
    _org_id_ctx.set(org_id)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash)."""
    raw = f"ps_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    key_hash = hash_api_key(raw)
    return raw, prefix, key_hash


def resolve_org_from_api_key(db: Session, raw_key: str) -> Optional[int]:
    h = hash_api_key(raw_key)
    key = db.query(ApiKey).filter(ApiKey.key_hash == h, ApiKey.revoked == False).first()
    if not key:
        return None
    return key.org_id


def resolve_org_from_user(db: Session, user: User) -> Optional[int]:
    """First org membership for a user."""
    member = db.query(OrgMember).filter(OrgMember.user_id == user.id).first()
    return member.org_id if member else None


def get_user_org_role(db: Session, user_id: int, org_id: int) -> Optional[str]:
    member = (
        db.query(OrgMember)
        .filter(OrgMember.user_id == user_id, OrgMember.org_id == org_id)
        .first()
    )
    return member.role if member else None


def create_org(db: Session, name: str, slug: str, creator: User) -> Organization:
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.flush()
    db.add(OrgMember(org_id=org.id, user_id=creator.id, role="admin"))
    db.commit()
    db.refresh(org)
    return org


def require_org_role(*roles: str):
    """Dependency: user must belong to current org with one of the given roles."""
    allowed = set(roles)

    def _dep(
        request: Request,
        db: Session = Depends(get_db),
    ):
        from auth import get_current_user
        user = get_current_user(request, db)
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        org_id = get_org_id()
        if org_id is None:
            raise HTTPException(status_code=400, detail="No organization context")
        role = get_user_org_role(db, user.id, org_id)
        if role is None or (allowed and role not in allowed):
            raise HTTPException(status_code=403, detail="Insufficient org role")
        return user

    return _dep
