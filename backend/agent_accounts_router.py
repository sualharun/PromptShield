from __future__ import annotations

from datetime import datetime, timezone
from typing import List
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from mongo import C, col


router = APIRouter(prefix="/api/agents/accounts", tags=["agents"])

_ALLOWED_PROVIDERS = {"codex", "claude", "cursor"}


class AgentAccountCreate(BaseModel):
    provider: str
    displayName: str
    githubHandle: str
    repoScope: str = ""


class AgentAccountOut(BaseModel):
    id: str
    provider: str
    displayName: str
    githubHandle: str
    repoScope: str
    createdAt: str


def _normalize_handle(value: str) -> str:
    return str(value or "").strip().lstrip("@").lower()


def _to_out(doc: dict) -> AgentAccountOut:
    created_at = doc.get("created_at")
    if isinstance(created_at, datetime):
        created_at_text = created_at.astimezone(timezone.utc).isoformat()
    else:
        created_at_text = str(created_at or datetime.now(timezone.utc).isoformat())
    return AgentAccountOut(
        id=str(doc.get("id") or ""),
        provider=str(doc.get("provider") or ""),
        displayName=str(doc.get("display_name") or ""),
        githubHandle=str(doc.get("github_handle") or ""),
        repoScope=str(doc.get("repo_scope") or ""),
        createdAt=created_at_text,
    )


@router.get("", response_model=List[AgentAccountOut])
def list_agent_accounts():
    docs = (
        col(C.AGENT_ACCOUNTS)
        .find({}, {"_id": 0})
        .sort("created_at", -1)
    )
    return [_to_out(doc) for doc in docs]


@router.post("", response_model=AgentAccountOut)
def create_agent_account(body: AgentAccountCreate):
    provider = str(body.provider or "").strip().lower()
    if provider not in _ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")

    github_handle = _normalize_handle(body.githubHandle)
    if not github_handle:
        raise HTTPException(status_code=400, detail="GitHub handle is required")

    repo_scope = str(body.repoScope or "").strip().lower()
    query = {
        "provider": provider,
        "github_handle": github_handle,
        "repo_scope": repo_scope,
    }
    if col(C.AGENT_ACCOUNTS).find_one(query, {"_id": 1}):
        raise HTTPException(
            status_code=409,
            detail="That provider and GitHub handle are already connected for this scope",
        )

    now = datetime.now(timezone.utc)
    doc = {
        "id": str(uuid4()),
        "provider": provider,
        "display_name": str(body.displayName or "").strip() or f"{provider} account",
        "github_handle": github_handle,
        "repo_scope": repo_scope,
        "created_at": now,
    }
    col(C.AGENT_ACCOUNTS).insert_one(doc)
    return _to_out(doc)


@router.delete("/{account_id}")
def delete_agent_account(account_id: str):
    deleted = col(C.AGENT_ACCOUNTS).delete_one({"id": account_id}).deleted_count
    if not deleted:
        raise HTTPException(status_code=404, detail="Agent account not found")
    return {"ok": True}
