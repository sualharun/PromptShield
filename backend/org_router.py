"""Organization management endpoints.

Provides CRUD for orgs, membership management, and API key provisioning.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import get_current_user, require_role
from database import User, get_db
from models import ApiKey, OrgMember, Organization
from tenant import create_org, generate_api_key, hash_api_key

router = APIRouter(prefix="/api/orgs", tags=["organizations"])


class CreateOrgRequest(BaseModel):
    name: str
    slug: str


class OrgResponse(BaseModel):
    id: int
    name: str
    slug: str
    plan: str
    settings: dict
    member_count: int


class InviteMemberRequest(BaseModel):
    email: str
    role: str = "viewer"


class MemberResponse(BaseModel):
    id: int
    user_id: int
    email: str
    name: str
    role: str


class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: str = "scan:write,scan:read"


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: str
    created_at: str
    revoked: bool


class ApiKeyCreatedResponse(ApiKeyResponse):
    raw_key: str


class UpdateOrgSettingsRequest(BaseModel):
    settings: dict


@router.post("", response_model=OrgResponse)
def create_organization(
    body: CreateOrgRequest,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    existing = db.query(Organization).filter(Organization.slug == body.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail="Slug already taken")
    org = create_org(db, body.name, body.slug, user)
    return _org_response(db, org)


@router.get("", response_model=List[OrgResponse])
def list_orgs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    memberships = db.query(OrgMember).filter(OrgMember.user_id == user.id).all()
    org_ids = [m.org_id for m in memberships]
    orgs = db.query(Organization).filter(Organization.id.in_(org_ids)).all() if org_ids else []
    return [_org_response(db, o) for o in orgs]


@router.get("/{org_id}", response_model=OrgResponse)
def get_org(
    org_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    member = (
        db.query(OrgMember)
        .filter(OrgMember.org_id == org_id, OrgMember.user_id == user.id)
        .first()
    )
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return _org_response(db, org)


@router.put("/{org_id}/settings")
def update_org_settings(
    org_id: int,
    body: UpdateOrgSettingsRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    member = (
        db.query(OrgMember)
        .filter(OrgMember.org_id == org_id, OrgMember.user_id == user.id)
        .first()
    )
    if not member or member.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org.settings_json = json.dumps(body.settings)
    db.commit()
    return {"ok": True}


@router.get("/{org_id}/members", response_model=List[MemberResponse])
def list_members(
    org_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_member(db, org_id, user.id)
    members = db.query(OrgMember).filter(OrgMember.org_id == org_id).all()
    result = []
    for m in members:
        u = db.query(User).filter(User.id == m.user_id).first()
        if u:
            result.append(MemberResponse(
                id=m.id, user_id=u.id, email=u.email, name=u.name, role=m.role
            ))
    return result


@router.post("/{org_id}/members", response_model=MemberResponse)
def invite_member(
    org_id: int,
    body: InviteMemberRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_admin(db, org_id, user.id)
    target = db.query(User).filter(User.email == body.email.lower().strip()).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    existing = (
        db.query(OrgMember)
        .filter(OrgMember.org_id == org_id, OrgMember.user_id == target.id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Already a member")
    if body.role not in ("admin", "pm", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    member = OrgMember(org_id=org_id, user_id=target.id, role=body.role)
    db.add(member)
    db.commit()
    db.refresh(member)
    return MemberResponse(
        id=member.id, user_id=target.id, email=target.email, name=target.name, role=member.role
    )


@router.delete("/{org_id}/members/{member_id}", status_code=204)
def remove_member(
    org_id: int,
    member_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_admin(db, org_id, user.id)
    member = db.query(OrgMember).filter(OrgMember.id == member_id, OrgMember.org_id == org_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    db.delete(member)
    db.commit()


@router.post("/{org_id}/api-keys", response_model=ApiKeyCreatedResponse)
def create_api_key(
    org_id: int,
    body: CreateApiKeyRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_admin(db, org_id, user.id)
    raw, prefix, key_hash = generate_api_key()
    key = ApiKey(
        org_id=org_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=prefix,
        scopes=body.scopes,
        created_by=user.id,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return ApiKeyCreatedResponse(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes,
        created_at=key.created_at.isoformat(),
        revoked=False,
        raw_key=raw,
    )


@router.get("/{org_id}/api-keys", response_model=List[ApiKeyResponse])
def list_api_keys(
    org_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_member(db, org_id, user.id)
    keys = db.query(ApiKey).filter(ApiKey.org_id == org_id).all()
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes,
            created_at=k.created_at.isoformat(),
            revoked=k.revoked,
        )
        for k in keys
    ]


@router.delete("/{org_id}/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    org_id: int,
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    _assert_admin(db, org_id, user.id)
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.org_id == org_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.revoked = True
    db.commit()


def _assert_member(db: Session, org_id: int, user_id: int):
    member = (
        db.query(OrgMember)
        .filter(OrgMember.org_id == org_id, OrgMember.user_id == user_id)
        .first()
    )
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this organization")


def _assert_admin(db: Session, org_id: int, user_id: int):
    member = (
        db.query(OrgMember)
        .filter(OrgMember.org_id == org_id, OrgMember.user_id == user_id)
        .first()
    )
    if not member or member.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


def _org_response(db: Session, org: Organization) -> OrgResponse:
    count = db.query(OrgMember).filter(OrgMember.org_id == org.id).count()
    return OrgResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        plan=org.plan,
        settings=json.loads(org.settings_json or "{}"),
        member_count=count,
    )
