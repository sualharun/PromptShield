"""Enterprise workflow router: lifecycle, SLA, diff, risk acceptance, and event stream."""

import json
from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import (
    FindingRecord,
    FindingRecordEvent,
    IntegrationEvent,
    RiskAcceptance,
    Scan,
    get_db,
)
from suppression import finding_signature

router = APIRouter(prefix="/api/workflow", tags=["workflow"])

ALLOWED_STATUSES = {
    "new",
    "triaged",
    "in_progress",
    "fixed",
    "verified",
    "suppressed",
    "risk_accepted",
    "closed",
}
SLA_HOURS = {"critical": 24, "high": 72, "medium": 168, "low": 336}


class FindingRecordRow(BaseModel):
    id: int
    signature: str
    scan_id: int
    last_seen_scan_id: int
    repo_full_name: Optional[str] = None
    pr_number: Optional[int] = None
    finding_type: str
    finding_title: str
    severity: str
    status: str
    owner: Optional[str] = None
    team: Optional[str] = None
    first_seen_at: str
    last_seen_at: str
    sla_due_at: Optional[str] = None
    is_active: bool


class FindingTransitionRequest(BaseModel):
    status: Literal[
        "new",
        "triaged",
        "in_progress",
        "fixed",
        "verified",
        "suppressed",
        "risk_accepted",
        "closed",
    ]
    actor: str = "anonymous"
    note: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None


class RiskAcceptanceRequest(BaseModel):
    reason: str
    approved_by: str = "security"
    expires_in_days: Optional[int] = 30


class IntegrationEventRow(BaseModel):
    id: int
    topic: str
    delivered: bool
    attempts: int
    created_at: str
    delivered_at: Optional[str] = None
    payload: dict


class WorkflowMetrics(BaseModel):
    total_open: int
    open_critical: int
    open_high: int
    sla_breaches: int
    mttr_hours: float
    risk_acceptances_active: int


@router.post("/sync/{scan_id}")
def sync_scan_to_workflow(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    synced = _sync_scan_findings(db, scan)
    db.commit()
    return {"scan_id": scan_id, "synced": synced}


@router.get("/findings", response_model=List[FindingRecordRow])
def list_workflow_findings(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
):
    q = db.query(FindingRecord)
    if status:
        q = q.filter(FindingRecord.status == status)
    if repo:
        q = q.filter(FindingRecord.repo_full_name == repo)
    if severity:
        q = q.filter(FindingRecord.severity == severity)
    if owner:
        q = q.filter(FindingRecord.owner == owner)
    if active_only:
        q = q.filter(FindingRecord.is_active == True)  # noqa: E712
    rows = q.order_by(FindingRecord.last_seen_at.desc()).limit(limit).all()
    return [_to_row(r) for r in rows]


@router.patch("/findings/{finding_id}", response_model=FindingRecordRow)
def transition_finding(
    finding_id: int,
    body: FindingTransitionRequest,
    db: Session = Depends(get_db),
):
    row = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")

    old_status = row.status
    row.status = body.status
    now = datetime.utcnow()

    if body.owner is not None:
        row.owner = body.owner
    if body.team is not None:
        row.team = body.team

    if body.status == "triaged":
        row.triaged_at = now
    elif body.status == "in_progress":
        row.in_progress_at = now
    elif body.status == "fixed":
        row.fixed_at = now
        row.is_active = False
    elif body.status == "verified":
        row.verified_at = now
        row.is_active = False
    elif body.status == "suppressed":
        row.suppressed_at = now
        row.is_active = False
    elif body.status == "closed":
        row.closed_at = now
        row.is_active = False
    elif body.status == "risk_accepted":
        row.is_active = True

    _add_finding_event(
        db,
        row.id,
        "status_transition",
        body.actor,
        {
            "from": old_status,
            "to": body.status,
            "note": body.note,
            "owner": row.owner,
            "team": row.team,
        },
    )
    _emit_integration_event(
        db,
        "finding.updated",
        {
            "finding_id": row.id,
            "signature": row.signature,
            "repo": row.repo_full_name,
            "status": row.status,
            "severity": row.severity,
            "actor": body.actor,
        },
    )

    db.commit()
    db.refresh(row)
    return _to_row(row)


@router.post("/findings/{finding_id}/accept-risk")
def accept_risk(
    finding_id: int,
    body: RiskAcceptanceRequest,
    db: Session = Depends(get_db),
):
    row = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")

    expires_at = None
    if body.expires_in_days and body.expires_in_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)

    acceptance = RiskAcceptance(
        finding_record_id=row.id,
        reason=body.reason,
        approved_by=body.approved_by,
        expires_at=expires_at,
        active=True,
    )
    row.status = "risk_accepted"
    row.is_active = True

    db.add(acceptance)
    _add_finding_event(
        db,
        row.id,
        "risk_accepted",
        body.approved_by,
        {
            "reason": body.reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    _emit_integration_event(
        db,
        "finding.risk_accepted",
        {
            "finding_id": row.id,
            "signature": row.signature,
            "repo": row.repo_full_name,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "approved_by": body.approved_by,
        },
    )

    db.commit()
    return {"ok": True, "finding_id": row.id, "status": row.status}


@router.get("/metrics", response_model=WorkflowMetrics)
def workflow_metrics(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    open_rows = db.query(FindingRecord).filter(FindingRecord.is_active == True).all()  # noqa: E712
    total_open = len(open_rows)
    open_critical = sum(1 for r in open_rows if r.severity == "critical")
    open_high = sum(1 for r in open_rows if r.severity == "high")
    sla_breaches = sum(
        1
        for r in open_rows
        if r.sla_due_at is not None and r.sla_due_at < now and r.status not in {"fixed", "verified", "suppressed", "closed"}
    )

    fixed_rows = db.query(FindingRecord).filter(FindingRecord.fixed_at.isnot(None)).all()
    mttr_hours = 0.0
    if fixed_rows:
        total = 0.0
        count = 0
        for r in fixed_rows:
            if r.first_seen_at and r.fixed_at:
                total += (r.fixed_at - r.first_seen_at).total_seconds() / 3600.0
                count += 1
        mttr_hours = round(total / max(1, count), 2)

    accepted_active = db.query(RiskAcceptance).filter(RiskAcceptance.active == True).count()  # noqa: E712

    return WorkflowMetrics(
        total_open=total_open,
        open_critical=open_critical,
        open_high=open_high,
        sla_breaches=sla_breaches,
        mttr_hours=mttr_hours,
        risk_acceptances_active=accepted_active,
    )


@router.get("/changes/{scan_id}")
def scan_changes(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    repo = scan.repo_full_name
    if not repo:
        return {"scan_id": scan.id, "added": [], "resolved": [], "persistent": []}

    prev = (
        db.query(Scan)
        .filter(
            Scan.repo_full_name == repo,
            Scan.id < scan.id,
        )
        .order_by(Scan.id.desc())
        .first()
    )

    current_findings = json.loads(scan.findings_json or "[]")
    current_map = {_sig(f): f for f in current_findings}

    if not prev:
        return {
            "scan_id": scan.id,
            "base_scan_id": None,
            "added": [current_map[k] for k in current_map],
            "resolved": [],
            "persistent": [],
        }

    prev_findings = json.loads(prev.findings_json or "[]")
    prev_map = {_sig(f): f for f in prev_findings}

    added_keys = [k for k in current_map if k not in prev_map]
    resolved_keys = [k for k in prev_map if k not in current_map]
    persistent_keys = [k for k in current_map if k in prev_map]

    return {
        "scan_id": scan.id,
        "base_scan_id": prev.id,
        "added": [current_map[k] for k in added_keys],
        "resolved": [prev_map[k] for k in resolved_keys],
        "persistent": [current_map[k] for k in persistent_keys],
        "delta": {
            "added": len(added_keys),
            "resolved": len(resolved_keys),
            "persistent": len(persistent_keys),
        },
    }


@router.get("/events", response_model=List[IntegrationEventRow])
def integration_events(
    db: Session = Depends(get_db),
    topic: Optional[str] = Query(None),
    undelivered_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=1000),
):
    q = db.query(IntegrationEvent).order_by(IntegrationEvent.created_at.desc())
    if topic:
        q = q.filter(IntegrationEvent.topic == topic)
    if undelivered_only:
        q = q.filter(IntegrationEvent.delivered == False)  # noqa: E712
    rows = q.limit(limit).all()
    return [
        IntegrationEventRow(
            id=r.id,
            topic=r.topic,
            delivered=bool(r.delivered),
            attempts=r.attempts,
            created_at=r.created_at.isoformat(),
            delivered_at=r.delivered_at.isoformat() if r.delivered_at else None,
            payload=json.loads(r.payload_json or "{}"),
        )
        for r in rows
    ]


@router.post("/events/{event_id}/delivered")
def mark_event_delivered(event_id: int, db: Session = Depends(get_db)):
    row = db.query(IntegrationEvent).filter(IntegrationEvent.id == event_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="event not found")
    row.delivered = True
    row.attempts = int(row.attempts or 0) + 1
    row.delivered_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "event_id": row.id, "delivered": True}


def _sync_scan_findings(db: Session, scan: Scan) -> int:
    findings = json.loads(scan.findings_json or "[]")
    synced = 0
    for f in findings:
        sig = _sig(f)
        if not sig:
            continue

        existing = (
            db.query(FindingRecord)
            .filter(FindingRecord.signature == sig)
            .filter(FindingRecord.repo_full_name == scan.repo_full_name)
            .first()
        )

        sev = (f.get("severity") or "low").lower()
        sla_due = scan.created_at + timedelta(hours=SLA_HOURS.get(sev, 336))

        if existing:
            existing.last_seen_scan_id = scan.id
            existing.last_seen_at = scan.created_at
            existing.is_active = True
            existing.severity = sev
            existing.pr_number = scan.pr_number
            existing.scan_id = existing.scan_id or scan.id
            existing.sla_due_at = existing.sla_due_at or sla_due
            existing.metadata_json = json.dumps(f)
        else:
            existing = FindingRecord(
                signature=sig,
                scan_id=scan.id,
                last_seen_scan_id=scan.id,
                repo_full_name=scan.repo_full_name,
                pr_number=scan.pr_number,
                finding_type=str(f.get("type") or "UNKNOWN"),
                finding_title=str(f.get("title") or "Untitled")[:255],
                severity=sev,
                status="new",
                first_seen_at=scan.created_at,
                last_seen_at=scan.created_at,
                sla_due_at=sla_due,
                is_active=True,
                metadata_json=json.dumps(f),
            )
            db.add(existing)
            db.flush()
            _add_finding_event(
                db,
                existing.id,
                "created",
                "system",
                {
                    "scan_id": scan.id,
                    "repo": scan.repo_full_name,
                    "severity": sev,
                },
            )
            _emit_integration_event(
                db,
                "finding.created",
                {
                    "finding_id": existing.id,
                    "signature": existing.signature,
                    "repo": existing.repo_full_name,
                    "severity": existing.severity,
                    "status": existing.status,
                },
            )
        synced += 1

    _mark_disappeared_findings_closed(db, scan, { _sig(f) for f in findings if _sig(f) })
    return synced


def _mark_disappeared_findings_closed(db: Session, scan: Scan, seen_sigs: set[str]) -> None:
    if not scan.repo_full_name:
        return
    rows = (
        db.query(FindingRecord)
        .filter(FindingRecord.repo_full_name == scan.repo_full_name)
        .filter(FindingRecord.is_active == True)  # noqa: E712
        .all()
    )
    for row in rows:
        if row.signature in seen_sigs:
            continue
        if row.status in {"fixed", "verified", "suppressed", "closed"}:
            continue
        row.status = "closed"
        row.closed_at = datetime.utcnow()
        row.is_active = False
        _add_finding_event(
            db,
            row.id,
            "auto_closed",
            "system",
            {"scan_id": scan.id, "reason": "No longer present in latest scan"},
        )
        _emit_integration_event(
            db,
            "finding.updated",
            {
                "finding_id": row.id,
                "signature": row.signature,
                "repo": row.repo_full_name,
                "status": row.status,
                "severity": row.severity,
                "actor": "system",
            },
        )


def _add_finding_event(db: Session, finding_record_id: int, event_type: str, actor: str, details: dict) -> None:
    db.add(
        FindingRecordEvent(
            finding_record_id=finding_record_id,
            event_type=event_type,
            actor=actor,
            details_json=json.dumps(details or {}),
        )
    )


def _emit_integration_event(db: Session, topic: str, payload: dict) -> None:
    db.add(
        IntegrationEvent(
            topic=topic,
            payload_json=json.dumps(payload or {}),
            delivered=False,
            attempts=0,
        )
    )


def _sig(finding: dict) -> str:
    try:
        return finding_signature(finding)
    except Exception:
        title = str(finding.get("title") or "")
        ftype = str(finding.get("type") or "UNKNOWN")
        sev = str(finding.get("severity") or "low")
        return f"{ftype}:{sev}:{title}"[:128]


def _to_row(r: FindingRecord) -> FindingRecordRow:
    return FindingRecordRow(
        id=r.id,
        signature=r.signature,
        scan_id=r.scan_id,
        last_seen_scan_id=r.last_seen_scan_id,
        repo_full_name=r.repo_full_name,
        pr_number=r.pr_number,
        finding_type=r.finding_type,
        finding_title=r.finding_title,
        severity=r.severity,
        status=r.status,
        owner=r.owner,
        team=r.team,
        first_seen_at=r.first_seen_at.isoformat() if r.first_seen_at else datetime.now(timezone.utc).isoformat(),
        last_seen_at=r.last_seen_at.isoformat() if r.last_seen_at else datetime.now(timezone.utc).isoformat(),
        sla_due_at=r.sla_due_at.isoformat() if r.sla_due_at else None,
        is_active=bool(r.is_active),
    )
