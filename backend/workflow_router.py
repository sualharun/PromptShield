"""Enterprise workflow router: lifecycle, SLA, diff, risk acceptance, and event stream.

v0.4: Mongo-backed. All `FindingRecord`, `IntegrationEvent`, and `RiskAcceptance`
work goes through `repositories`. IDs in the API are now `str` (Mongo `_id`),
which the frontend already tolerates because we read them as opaque strings.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import repositories as repos
from mongo import C, col
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
    id: str
    signature: str
    scan_id: Optional[str] = None
    last_seen_scan_id: Optional[str] = None
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
    id: str
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


# ── Helpers ────────────────────────────────────────────────────────────────
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: Optional[datetime]) -> Optional[str]:
    dt = _to_aware(dt)
    return dt.isoformat() if dt else None


def _to_row(doc: dict) -> FindingRecordRow:
    return FindingRecordRow(
        id=str(doc.get("_id")),
        signature=doc.get("signature") or "",
        scan_id=str(doc["scan_id"]) if doc.get("scan_id") else None,
        last_seen_scan_id=str(doc["last_seen_scan_id"]) if doc.get("last_seen_scan_id") else None,
        repo_full_name=doc.get("repo_full_name"),
        pr_number=doc.get("pr_number"),
        finding_type=str(doc.get("finding_type") or "UNKNOWN"),
        finding_title=str(doc.get("finding_title") or "Untitled"),
        severity=str(doc.get("severity") or "low"),
        status=str(doc.get("status") or "new"),
        owner=doc.get("owner"),
        team=doc.get("team"),
        first_seen_at=_iso(doc.get("first_seen_at")) or _utcnow().isoformat(),
        last_seen_at=_iso(doc.get("last_seen_at")) or _utcnow().isoformat(),
        sla_due_at=_iso(doc.get("sla_due_at")),
        is_active=bool(doc.get("is_active", True)),
    )


def _sig(finding: dict) -> str:
    try:
        return finding_signature(finding)
    except Exception:
        title = str(finding.get("title") or "")
        ftype = str(finding.get("type") or "UNKNOWN")
        sev = str(finding.get("severity") or "low")
        return f"{ftype}:{sev}:{title}"[:128]


def _emit_event(topic: str, payload: dict) -> None:
    repos.insert_integration_event(
        {
            "topic": topic,
            "payload": payload or {},
            "delivered": False,
            "attempts": 0,
        }
    )


# ── Routes ──────────────────────────────────────────────────────────────────
@router.post("/sync/{scan_id}")
def sync_scan_to_workflow(scan_id: str):
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    synced = _sync_scan_findings(scan)
    return {"scan_id": str(scan.get("_id")), "synced": synced}


@router.get("/findings", response_model=List[FindingRecordRow])
def list_workflow_findings(
    status: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
):
    rows = repos.list_finding_records_filtered(
        status=status,
        repo=repo,
        severity=severity,
        owner=owner,
        active_only=active_only,
        limit=limit,
    )
    return [_to_row(r) for r in rows]


@router.patch("/findings/{finding_id}", response_model=FindingRecordRow)
def transition_finding(finding_id: str, body: FindingTransitionRequest):
    row = repos.get_finding_record(finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")

    old_status = row.get("status") or "new"
    fields: dict = {"status": body.status}
    now = _utcnow()

    if body.owner is not None:
        fields["owner"] = body.owner
    if body.team is not None:
        fields["team"] = body.team

    if body.status == "triaged":
        fields["triaged_at"] = now
    elif body.status == "in_progress":
        fields["in_progress_at"] = now
    elif body.status == "fixed":
        fields["fixed_at"] = now
        fields["is_active"] = False
    elif body.status == "verified":
        fields["verified_at"] = now
        fields["is_active"] = False
    elif body.status == "suppressed":
        fields["suppressed_at"] = now
        fields["is_active"] = False
    elif body.status == "closed":
        fields["closed_at"] = now
        fields["is_active"] = False
    elif body.status == "risk_accepted":
        fields["is_active"] = True

    repos.update_finding_record(finding_id, fields)
    updated = repos.get_finding_record(finding_id) or {**row, **fields}

    repos.insert_finding_event(
        finding_record_id=finding_id,
        event_type="status_transition",
        actor=body.actor,
        details={
            "from": old_status,
            "to": body.status,
            "note": body.note,
            "owner": updated.get("owner"),
            "team": updated.get("team"),
        },
    )
    _emit_event(
        "finding.updated",
        {
            "finding_id": str(updated.get("_id")),
            "signature": updated.get("signature"),
            "repo": updated.get("repo_full_name"),
            "status": updated.get("status"),
            "severity": updated.get("severity"),
            "actor": body.actor,
        },
    )

    return _to_row(updated)


@router.post("/findings/{finding_id}/accept-risk")
def accept_risk(finding_id: str, body: RiskAcceptanceRequest):
    row = repos.get_finding_record(finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")

    expires_at = None
    if body.expires_in_days and body.expires_in_days > 0:
        expires_at = _utcnow() + timedelta(days=body.expires_in_days)

    repos.insert_risk_acceptance(
        {
            "finding_record_id": finding_id,
            "reason": body.reason,
            "approved_by": body.approved_by,
            "expires_at": expires_at,
            "active": True,
        }
    )
    repos.update_finding_record(
        finding_id, {"status": "risk_accepted", "is_active": True}
    )
    repos.insert_finding_event(
        finding_record_id=finding_id,
        event_type="risk_accepted",
        actor=body.approved_by,
        details={
            "reason": body.reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    _emit_event(
        "finding.risk_accepted",
        {
            "finding_id": finding_id,
            "signature": row.get("signature"),
            "repo": row.get("repo_full_name"),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "approved_by": body.approved_by,
        },
    )

    return {"ok": True, "finding_id": finding_id, "status": "risk_accepted"}


@router.get("/metrics", response_model=WorkflowMetrics)
def workflow_metrics():
    now = _utcnow()
    open_rows = list(col(C.FINDING_RECORDS).find({"is_active": True}))
    total_open = len(open_rows)
    open_critical = sum(1 for r in open_rows if r.get("severity") == "critical")
    open_high = sum(1 for r in open_rows if r.get("severity") == "high")
    sla_breaches = 0
    for r in open_rows:
        sla = _to_aware(r.get("sla_due_at"))
        if (
            sla is not None
            and sla < now
            and r.get("status") not in {"fixed", "verified", "suppressed", "closed"}
        ):
            sla_breaches += 1

    fixed_rows = list(col(C.FINDING_RECORDS).find({"fixed_at": {"$ne": None}}))
    mttr_hours = 0.0
    if fixed_rows:
        total = 0.0
        count = 0
        for r in fixed_rows:
            first = _to_aware(r.get("first_seen_at"))
            fixed = _to_aware(r.get("fixed_at"))
            if first and fixed:
                total += (fixed - first).total_seconds() / 3600.0
                count += 1
        mttr_hours = round(total / max(1, count), 2)

    return WorkflowMetrics(
        total_open=total_open,
        open_critical=open_critical,
        open_high=open_high,
        sla_breaches=sla_breaches,
        mttr_hours=mttr_hours,
        risk_acceptances_active=repos.count_active_risk_acceptances(),
    )


@router.get("/changes/{scan_id}")
def scan_changes(scan_id: str):
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    repo = (scan.get("github") or {}).get("repo_full_name")
    if not repo:
        return {"scan_id": str(scan.get("_id")), "added": [], "resolved": [], "persistent": []}

    prev = (
        col(C.SCANS)
        .find(
            {
                "github.repo_full_name": repo,
                "created_at": {"$lt": scan.get("created_at") or _utcnow()},
            }
        )
        .sort("created_at", -1)
        .limit(1)
    )
    prev_doc = next(iter(prev), None)

    current_findings = list(scan.get("findings") or [])
    current_map = {_sig(f): f for f in current_findings}

    if not prev_doc:
        return {
            "scan_id": str(scan.get("_id")),
            "base_scan_id": None,
            "added": list(current_map.values()),
            "resolved": [],
            "persistent": [],
        }

    prev_findings = list(prev_doc.get("findings") or [])
    prev_map = {_sig(f): f for f in prev_findings}

    added_keys = [k for k in current_map if k not in prev_map]
    resolved_keys = [k for k in prev_map if k not in current_map]
    persistent_keys = [k for k in current_map if k in prev_map]

    return {
        "scan_id": str(scan.get("_id")),
        "base_scan_id": str(prev_doc.get("_id")),
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
    topic: Optional[str] = Query(None),
    undelivered_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=1000),
):
    rows = repos.list_integration_events(
        topic=topic, undelivered_only=undelivered_only, limit=limit
    )
    return [
        IntegrationEventRow(
            id=str(r.get("_id")),
            topic=str(r.get("topic") or ""),
            delivered=bool(r.get("delivered")),
            attempts=int(r.get("attempts") or 0),
            created_at=_iso(r.get("created_at")) or _utcnow().isoformat(),
            delivered_at=_iso(r.get("delivered_at")),
            payload=r.get("payload") or {},
        )
        for r in rows
    ]


@router.post("/events/{event_id}/delivered")
def mark_event_delivered(event_id: str):
    row = repos.get_integration_event(event_id)
    if not row:
        raise HTTPException(status_code=404, detail="event not found")
    repos.update_integration_event(
        event_id,
        {
            "delivered": True,
            "attempts": int(row.get("attempts") or 0) + 1,
            "delivered_at": _utcnow(),
        },
    )
    return {"ok": True, "event_id": event_id, "delivered": True}


# ── Sync helpers ────────────────────────────────────────────────────────────
def _sync_scan_findings(scan: dict) -> int:
    findings = list(scan.get("findings") or [])
    repo = (scan.get("github") or {}).get("repo_full_name")
    pr_number = (scan.get("github") or {}).get("pr_number")
    scan_id = str(scan.get("_id"))
    scan_created_at = _to_aware(scan.get("created_at")) or _utcnow()

    synced = 0
    seen_sigs: set[str] = set()
    for f in findings:
        sig = _sig(f)
        if not sig:
            continue
        seen_sigs.add(sig)

        existing = repos.find_finding_record(signature=sig, repo_full_name=repo)
        sev = (f.get("severity") or "low").lower()
        sla_due = scan_created_at + timedelta(hours=SLA_HOURS.get(sev, 336))

        if existing:
            update_fields = {
                "last_seen_scan_id": scan_id,
                "last_seen_at": scan_created_at,
                "is_active": True,
                "severity": sev,
                "pr_number": pr_number,
                "metadata": f,
            }
            if not existing.get("scan_id"):
                update_fields["scan_id"] = scan_id
            if not existing.get("sla_due_at"):
                update_fields["sla_due_at"] = sla_due
            repos.update_finding_record(existing["_id"], update_fields)
        else:
            doc = repos.insert_finding_record(
                {
                    "signature": sig,
                    "scan_id": scan_id,
                    "last_seen_scan_id": scan_id,
                    "repo_full_name": repo,
                    "pr_number": pr_number,
                    "finding_type": str(f.get("type") or "UNKNOWN"),
                    "finding_title": str(f.get("title") or "Untitled")[:255],
                    "severity": sev,
                    "status": "new",
                    "first_seen_at": scan_created_at,
                    "last_seen_at": scan_created_at,
                    "sla_due_at": sla_due,
                    "is_active": True,
                    "metadata": f,
                }
            )
            repos.insert_finding_event(
                finding_record_id=doc["_id"],
                event_type="created",
                actor="system",
                details={
                    "scan_id": scan_id,
                    "repo": repo,
                    "severity": sev,
                },
            )
            _emit_event(
                "finding.created",
                {
                    "finding_id": str(doc["_id"]),
                    "signature": sig,
                    "repo": repo,
                    "severity": sev,
                    "status": "new",
                },
            )
        synced += 1

    _mark_disappeared_findings_closed(repo, scan_id, seen_sigs)
    return synced


def _mark_disappeared_findings_closed(
    repo: Optional[str], scan_id: str, seen_sigs: set[str]
) -> None:
    if not repo:
        return
    rows = repos.list_active_finding_records_for_repo(repo)
    for row in rows:
        if row.get("signature") in seen_sigs:
            continue
        if row.get("status") in {"fixed", "verified", "suppressed", "closed"}:
            continue
        repos.update_finding_record(
            row["_id"],
            {"status": "closed", "closed_at": _utcnow(), "is_active": False},
        )
        repos.insert_finding_event(
            finding_record_id=row["_id"],
            event_type="auto_closed",
            actor="system",
            details={"scan_id": scan_id, "reason": "No longer present in latest scan"},
        )
        _emit_event(
            "finding.updated",
            {
                "finding_id": str(row.get("_id")),
                "signature": row.get("signature"),
                "repo": row.get("repo_full_name"),
                "status": "closed",
                "severity": row.get("severity"),
                "actor": "system",
            },
        )
