"""Suppression REST endpoints — fully Mongo-backed (v0.4 port)."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import repositories as repos
from auth import SessionUser, get_current_user
from suppression import finding_signature


router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])


class SuppressRequest(BaseModel):
    finding: dict
    repo_full_name: Optional[str] = None
    reason: Optional[str] = None


class SuppressionRow(BaseModel):
    id: str
    signature: str
    finding_type: str
    finding_title: str
    repo_full_name: Optional[str] = None
    reason: Optional[str] = None
    suppressed_by: str
    created_at: str


def _to_row(doc: dict) -> SuppressionRow:
    v = repos.suppression_to_view(doc)
    return SuppressionRow(**v)


@router.get("", response_model=List[SuppressionRow])
def list_suppressions(repo: Optional[str] = None):
    rows = repos.list_suppressions(repo=repo)
    return [_to_row(r) for r in rows]


@router.post("", response_model=SuppressionRow)
def create_suppression(
    body: SuppressRequest,
    user: Optional[SessionUser] = Depends(get_current_user),
):
    sig = finding_signature(body.finding)
    doc = repos.upsert_suppression(
        signature=sig,
        finding_type=str(body.finding.get("type") or "UNKNOWN"),
        finding_title=str(body.finding.get("title") or ""),
        repo_full_name=body.repo_full_name,
        reason=body.reason,
        suppressed_by=user.email if user else "anonymous",
    )
    return _to_row(doc)


@router.delete("/{suppression_id}")
def delete_suppression(suppression_id: str):
    if not repos.delete_suppression(suppression_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}
