"""Operations endpoints: metrics, traces, SLOs, job queue, and command center.

The command center provides a real-time view of scan activity, trend anomalies,
finding ownership routing, and SLA breach tracking.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import AuditLog, Scan, get_db
from job_queue import job_queue
from models import ScanJob
from observability import metrics, slo_tracker, tracer

router = APIRouter(prefix="/api/ops", tags=["operations"])


@router.get("/metrics")
def get_metrics():
    return metrics.snapshot()


@router.get("/traces")
def get_traces(limit: int = Query(50, ge=1, le=200)):
    return {"spans": tracer.recent(limit)}


@router.get("/slos")
def get_slos():
    return slo_tracker.status()


@router.get("/jobs/queue")
def queue_status():
    return job_queue.queue_depth()


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    status = job_queue.get_status(job_id)
    if not status:
        return {"error": "Job not found"}
    return status


@router.get("/jobs/dead-letter/list")
def dead_letters():
    return {"dead_letter": job_queue.list_dead_letters()}


# ---------- Command Center ----------


class CommandCenterEvent(BaseModel):
    id: int
    timestamp: str
    event_type: str
    repo: Optional[str]
    pr_number: Optional[int]
    risk_score: Optional[int]
    severity_counts: Dict[str, int]
    author: Optional[str]
    gate_result: str


class TrendAnomaly(BaseModel):
    repo: str
    metric: str
    current_value: float
    baseline_value: float
    deviation_pct: float
    direction: str


class OwnershipRoute(BaseModel):
    author: str
    open_critical_high: int
    repos: List[str]
    avg_risk: float
    needs_attention: bool


@router.get("/command-center")
def command_center(
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=168),
):
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    recent_scans = (
        db.query(Scan)
        .filter(Scan.source == "github", Scan.created_at >= cutoff)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )

    events = []
    for s in recent_scans:
        findings = json.loads(s.findings_json or "[]")
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            if sev in counts:
                counts[sev] += 1
        gate = "fail" if (s.risk_score or 0) >= 70 else "pass"
        events.append({
            "id": s.id,
            "timestamp": s.created_at.isoformat(),
            "event_type": "pr_scan",
            "repo": s.repo_full_name,
            "pr_number": s.pr_number,
            "risk_score": int(s.risk_score or 0),
            "severity_counts": counts,
            "author": s.author_login,
            "gate_result": gate,
        })

    anomalies = _detect_anomalies(db, cutoff)
    ownership = _build_ownership(db, cutoff)
    sla_breaches = _check_sla_breaches(db, cutoff)

    return {
        "events": events,
        "anomalies": anomalies,
        "ownership_routing": ownership,
        "sla_breaches": sla_breaches,
        "window_hours": hours,
        "total_scans": len(recent_scans),
        "gate_failures": sum(1 for e in events if e["gate_result"] == "fail"),
    }


def _detect_anomalies(db: Session, cutoff: datetime) -> List[Dict]:
    """Compare recent risk per repo against its historical baseline."""
    all_github = db.query(Scan).filter(Scan.source == "github").all()
    baseline_cutoff = cutoff - timedelta(days=14)

    repo_baseline: Dict[str, List[float]] = defaultdict(list)
    repo_recent: Dict[str, List[float]] = defaultdict(list)

    for s in all_github:
        if not s.repo_full_name:
            continue
        if s.created_at >= cutoff:
            repo_recent[s.repo_full_name].append(float(s.risk_score or 0))
        elif s.created_at >= baseline_cutoff:
            repo_baseline[s.repo_full_name].append(float(s.risk_score or 0))

    anomalies = []
    for repo, recent_scores in repo_recent.items():
        baseline_scores = repo_baseline.get(repo, [])
        if len(baseline_scores) < 3:
            continue
        avg_recent = sum(recent_scores) / len(recent_scores)
        avg_baseline = sum(baseline_scores) / len(baseline_scores)
        if avg_baseline < 5:
            continue
        deviation = ((avg_recent - avg_baseline) / avg_baseline) * 100
        if abs(deviation) > 25:
            anomalies.append({
                "repo": repo,
                "metric": "avg_risk_score",
                "current_value": round(avg_recent, 1),
                "baseline_value": round(avg_baseline, 1),
                "deviation_pct": round(deviation, 1),
                "direction": "increasing" if deviation > 0 else "decreasing",
            })
    return sorted(anomalies, key=lambda a: -abs(a["deviation_pct"]))


def _build_ownership(db: Session, cutoff: datetime) -> List[Dict]:
    """Route findings to authors who need attention."""
    recent = (
        db.query(Scan)
        .filter(Scan.source == "github", Scan.created_at >= cutoff, Scan.author_login.isnot(None))
        .all()
    )

    author_data: Dict[str, Dict] = defaultdict(lambda: {
        "critical_high": 0, "repos": set(), "risk_sum": 0, "count": 0
    })

    for s in recent:
        data = author_data[s.author_login]
        data["count"] += 1
        data["risk_sum"] += float(s.risk_score or 0)
        if s.repo_full_name:
            data["repos"].add(s.repo_full_name)
        for f in json.loads(s.findings_json or "[]"):
            sev = (f.get("severity") or "low").lower()
            if sev in ("critical", "high"):
                data["critical_high"] += 1

    ownership = []
    for author, data in author_data.items():
        avg_risk = data["risk_sum"] / max(1, data["count"])
        ownership.append({
            "author": author,
            "open_critical_high": data["critical_high"],
            "repos": sorted(data["repos"]),
            "avg_risk": round(avg_risk, 1),
            "needs_attention": data["critical_high"] > 0 or avg_risk >= 60,
        })
    return sorted(ownership, key=lambda o: -o["open_critical_high"])


def _check_sla_breaches(db: Session, cutoff: datetime) -> List[Dict]:
    """Check for SLA violations: scans that took too long or repos without recent scans."""
    breaches = []

    recent_scans = (
        db.query(Scan)
        .filter(Scan.source == "github", Scan.created_at >= cutoff)
        .all()
    )

    repo_last_scan: Dict[str, datetime] = {}
    for s in recent_scans:
        if s.repo_full_name:
            existing = repo_last_scan.get(s.repo_full_name)
            if existing is None or s.created_at > existing:
                repo_last_scan[s.repo_full_name] = s.created_at

    all_repos = db.query(Scan.repo_full_name).filter(
        Scan.source == "github", Scan.repo_full_name.isnot(None)
    ).distinct().all()

    for (repo,) in all_repos:
        last = repo_last_scan.get(repo)
        if last is None:
            breaches.append({
                "type": "stale_repo",
                "repo": repo,
                "detail": "No scans in monitoring window",
                "severity": "warning",
            })

    high_risk_unresolved = (
        db.query(Scan)
        .filter(
            Scan.source == "github",
            Scan.risk_score >= 70,
            Scan.created_at >= cutoff,
        )
        .all()
    )
    for s in high_risk_unresolved:
        hours_open = (datetime.utcnow() - s.created_at).total_seconds() / 3600
        if hours_open > 24:
            breaches.append({
                "type": "unresolved_high_risk",
                "repo": s.repo_full_name,
                "pr_number": s.pr_number,
                "risk_score": int(s.risk_score),
                "hours_open": round(hours_open, 1),
                "detail": f"PR #{s.pr_number} has risk score {int(s.risk_score)} open for {round(hours_open)}h",
                "severity": "critical" if s.risk_score >= 85 else "high",
            })

    return sorted(breaches, key=lambda b: 0 if b["severity"] == "critical" else 1)
