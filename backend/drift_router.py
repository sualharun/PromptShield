"""Drift detection and baseline management endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from drift import (
    acknowledge_baseline,
    get_drift_summary,
    get_baseline_signatures,
)
from models import BaselineFinding

router = APIRouter(prefix="/api/drift", tags=["drift"])


@router.get("/summary/{repo_path:path}")
def drift_summary(repo_path: str, db: Session = Depends(get_db)):
    return get_drift_summary(db, repo_path)


@router.get("/baseline/{repo_path:path}")
def list_baseline(
    repo_path: str,
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(BaselineFinding).filter(BaselineFinding.repo_full_name == repo_path)
    if severity:
        q = q.filter(BaselineFinding.severity == severity.lower())
    if acknowledged is not None:
        q = q.filter(BaselineFinding.acknowledged == acknowledged)
    rows = q.order_by(BaselineFinding.last_seen_at.desc()).limit(200).all()
    return {
        "repo": repo_path,
        "findings": [
            {
                "id": r.id,
                "signature": r.signature,
                "finding_type": r.finding_type,
                "severity": r.severity,
                "first_seen_at": r.first_seen_at.isoformat(),
                "last_seen_at": r.last_seen_at.isoformat(),
                "acknowledged": r.acknowledged,
                "acknowledged_by": r.acknowledged_by,
            }
            for r in rows
        ],
    }


class AcknowledgeRequest(BaseModel):
    signature: str
    acknowledged_by: str = "anonymous"


@router.post("/acknowledge/{repo_path:path}")
def acknowledge(
    repo_path: str,
    body: AcknowledgeRequest,
    db: Session = Depends(get_db),
):
    ok = acknowledge_baseline(db, repo_path, body.signature, body.acknowledged_by)
    if not ok:
        raise HTTPException(status_code=404, detail="Baseline finding not found")
    return {"ok": True}
