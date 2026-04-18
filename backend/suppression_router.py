from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import get_current_user
from database import FindingSuppression, User, get_db
from suppression import finding_signature


router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])


class SuppressRequest(BaseModel):
    finding: dict
    repo_full_name: Optional[str] = None
    reason: Optional[str] = None


class SuppressionRow(BaseModel):
    id: int
    signature: str
    finding_type: str
    finding_title: str
    repo_full_name: Optional[str] = None
    reason: Optional[str] = None
    suppressed_by: str
    created_at: str


def _to_row(s: FindingSuppression) -> SuppressionRow:
    return SuppressionRow(
        id=s.id,
        signature=s.signature,
        finding_type=s.finding_type,
        finding_title=s.finding_title,
        repo_full_name=s.repo_full_name,
        reason=s.reason,
        suppressed_by=s.suppressed_by,
        created_at=s.created_at.isoformat(),
    )


@router.get("", response_model=List[SuppressionRow])
def list_suppressions(db: Session = Depends(get_db)):
    rows = (
        db.query(FindingSuppression)
        .order_by(FindingSuppression.created_at.desc())
        .all()
    )
    return [_to_row(r) for r in rows]


@router.post("", response_model=SuppressionRow)
def create_suppression(
    body: SuppressRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
):
    sig = finding_signature(body.finding)
    existing = (
        db.query(FindingSuppression)
        .filter(FindingSuppression.signature == sig)
        .filter(FindingSuppression.repo_full_name == body.repo_full_name)
        .first()
    )
    if existing:
        return _to_row(existing)
    row = FindingSuppression(
        signature=sig,
        finding_type=str(body.finding.get("type") or "UNKNOWN"),
        finding_title=str(body.finding.get("title") or "")[:255],
        repo_full_name=body.repo_full_name,
        reason=body.reason,
        suppressed_by=user.email if user else "anonymous",
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_row(row)


@router.delete("/{suppression_id}")
def delete_suppression(
    suppression_id: int,
    db: Session = Depends(get_db),
):
    row = (
        db.query(FindingSuppression)
        .filter(FindingSuppression.id == suppression_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(row)
    db.commit()
    return {"ok": True}
