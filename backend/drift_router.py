"""Drift detection and baseline management endpoints — Mongo-backed (v0.4)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import repositories as repos


router = APIRouter(prefix="/api/drift", tags=["drift"])


@router.get("/summary/{repo_path:path}")
def drift_summary(repo_path: str):
    return repos.baseline_summary(repo_path)


@router.get("/baseline/{repo_path:path}")
def list_baseline(
    repo_path: str,
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
):
    rows = repos.list_baseline(
        repo=repo_path, severity=severity, acknowledged=acknowledged
    )
    return {
        "repo": repo_path,
        "findings": [repos.baseline_to_view(r) for r in rows],
    }


class AcknowledgeRequest(BaseModel):
    signature: str
    acknowledged_by: str = "anonymous"


@router.post("/acknowledge/{repo_path:path}")
def acknowledge(repo_path: str, body: AcknowledgeRequest):
    if not repos.acknowledge_baseline(
        repo=repo_path, signature=body.signature, by=body.acknowledged_by
    ):
        raise HTTPException(status_code=404, detail="Baseline finding not found")
    return {"ok": True}
