"""Organization management endpoints — Mongo-backed (v0.4 port).

Members and API keys live as embedded arrays under each `organizations` doc.
This is the canonical NoSQL way to model 1:N data that's *always* fetched
together with the parent.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import repositories as repos
from auth import SessionUser, get_current_user, require_role
from mongo import C, col
from tenant import create_org as create_org_helper
from tenant import generate_api_key, hash_api_key  # noqa: F401  (re-export for tests)


router = APIRouter(prefix="/api/orgs", tags=["organizations"])


# ── Pydantic models ─────────────────────────────────────────────────────────
class CreateOrgRequest(BaseModel):
    name: str
    slug: str


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    settings: dict
    member_count: int


class InviteMemberRequest(BaseModel):
    email: str
    role: str = "viewer"


class MemberResponse(BaseModel):
    id: str
    user_id: str
    email: str
    name: str
    role: str


class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: str = "scan:write,scan:read"


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: str
    created_at: str
    revoked: bool


class ApiKeyCreatedResponse(ApiKeyResponse):
    raw_key: str


class UpdateOrgSettingsRequest(BaseModel):
    settings: dict


# ── Helpers ─────────────────────────────────────────────────────────────────
def _org_response(org: dict) -> OrgResponse:
    return OrgResponse(
        id=str(org["_id"]),
        name=org.get("name", ""),
        slug=org.get("slug", ""),
        plan=org.get("plan", "free"),
        settings=org.get("settings") or {},
        member_count=len(org.get("members") or []),
    )


def _member_id(org_id: str, user_id: str) -> str:
    """Synthetic stable id for an embedded member entry — used by remove_member."""
    return f"{org_id}:{user_id}"


def _assert_member(org: dict, user_id: str) -> dict:
    for m in org.get("members") or []:
        if str(m.get("user_id")) == user_id:
            return m
    raise HTTPException(status_code=403, detail="Not a member of this organization")


def _assert_admin(org: dict, user_id: str) -> dict:
    m = _assert_member(org, user_id)
    if m.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return m


def _require_org(org_id: str) -> dict:
    org = repos.get_org_by_id(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# ── Routes ──────────────────────────────────────────────────────────────────
@router.post("", response_model=OrgResponse)
def create_organization(
    body: CreateOrgRequest,
    user: SessionUser = Depends(require_role("admin")),
):
    if col(C.ORGANIZATIONS).find_one({"slug": body.slug.lower().strip()}):
        raise HTTPException(status_code=409, detail="Slug already taken")
    org = create_org_helper(None, body.name, body.slug, user)
    return _org_response(org)


@router.get("", response_model=List[OrgResponse])
def list_orgs(user: Optional[SessionUser] = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    cursor = col(C.ORGANIZATIONS).find({"members.user_id": str(user.id)})
    return [_org_response(o) for o in cursor]


@router.get("/{org_id}", response_model=OrgResponse)
def get_org(org_id: str, user: Optional[SessionUser] = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_member(org, str(user.id))
    return _org_response(org)


@router.put("/{org_id}/settings")
def update_org_settings(
    org_id: str,
    body: UpdateOrgSettingsRequest,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_admin(org, str(user.id))
    col(C.ORGANIZATIONS).update_one(
        {"_id": org["_id"]}, {"$set": {"settings": body.settings}}
    )
    return {"ok": True}


@router.get("/{org_id}/members", response_model=List[MemberResponse])
def list_members(
    org_id: str, user: Optional[SessionUser] = Depends(get_current_user)
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_member(org, str(user.id))
    out: List[MemberResponse] = []
    for m in org.get("members") or []:
        u = repos.get_user_by_id(m.get("user_id"))
        if u:
            out.append(
                MemberResponse(
                    id=_member_id(str(org["_id"]), str(u.get("_id"))),
                    user_id=str(u.get("_id")),
                    email=u.get("email") or "",
                    name=u.get("name") or "",
                    role=m.get("role") or "viewer",
                )
            )
    return out


@router.post("/{org_id}/members", response_model=MemberResponse)
def invite_member(
    org_id: str,
    body: InviteMemberRequest,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_admin(org, str(user.id))
    if body.role not in ("admin", "pm", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    target = repos.find_user_by_email(body.email.lower().strip())
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target_id = str(target.get("_id"))
    if any(str(m.get("user_id")) == target_id for m in org.get("members") or []):
        raise HTTPException(status_code=409, detail="Already a member")
    repos.add_org_member(org["_id"], user_id=target_id, role=body.role)
    return MemberResponse(
        id=_member_id(str(org["_id"]), target_id),
        user_id=target_id,
        email=target.get("email") or "",
        name=target.get("name") or "",
        role=body.role,
    )


@router.delete("/{org_id}/members/{member_id}", status_code=204)
def remove_member(
    org_id: str,
    member_id: str,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_admin(org, str(user.id))
    # member_id is "<org_id>:<user_id>" — we accept either the synthetic form
    # or just the user_id, to be friendly to clients.
    target_user_id = member_id.split(":", 1)[-1]
    res = col(C.ORGANIZATIONS).update_one(
        {"_id": org["_id"]},
        {"$pull": {"members": {"user_id": target_user_id}}},
    )
    if res.modified_count == 0:
        raise HTTPException(status_code=404, detail="Member not found")


@router.post("/{org_id}/api-keys", response_model=ApiKeyCreatedResponse)
def create_api_key(
    org_id: str,
    body: CreateApiKeyRequest,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_admin(org, str(user.id))
    raw, prefix, key_hash = generate_api_key()
    repos.add_api_key(
        org["_id"],
        name=body.name,
        key_hash=key_hash,
        key_prefix=prefix,
        scopes=body.scopes,
    )
    from datetime import datetime, timezone

    return ApiKeyCreatedResponse(
        id=f"{org_id}:{prefix}",
        name=body.name,
        key_prefix=prefix,
        scopes=body.scopes,
        created_at=datetime.now(timezone.utc).isoformat(),
        revoked=False,
        raw_key=raw,
    )


@router.get("/{org_id}/api-keys", response_model=List[ApiKeyResponse])
def list_api_keys(
    org_id: str, user: Optional[SessionUser] = Depends(get_current_user)
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_member(org, str(user.id))
    out: List[ApiKeyResponse] = []
    for k in org.get("api_keys") or []:
        out.append(
            ApiKeyResponse(
                id=f"{org_id}:{k.get('key_prefix')}",
                name=k.get("name") or "",
                key_prefix=k.get("key_prefix") or "",
                scopes=k.get("scopes") or "",
                created_at=(k.get("created_at")).isoformat()
                if k.get("created_at")
                else "",
                revoked=bool(k.get("revoked", False)),
            )
        )
    return out


@router.delete("/{org_id}/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    org_id: str,
    key_id: str,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    org = _require_org(org_id)
    _assert_admin(org, str(user.id))
    prefix = key_id.split(":", 1)[-1]
    res = col(C.ORGANIZATIONS).update_one(
        {"_id": org["_id"], "api_keys.key_prefix": prefix},
        {"$set": {"api_keys.$.revoked": True}},
    )
    if res.modified_count == 0:
        raise HTTPException(status_code=404, detail="API key not found")
