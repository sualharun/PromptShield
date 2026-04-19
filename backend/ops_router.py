"""Operations endpoints — Mongo-backed (v0.4 port).

Metrics, traces, SLOs, job queue, and the Command Center pipeline. The Command
Center surfaces real-time scan activity, cross-repo trend anomalies, finding
ownership routing, and SLA breach tracking — all read out of the `scans`
collection with a few small aggregation pipelines.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from job_queue import job_queue
from mongo import C, col
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


# ── Command Center ─────────────────────────────────────────────────────────
class CommandCenterEvent(BaseModel):
    id: str
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


def _ts_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.get("/command-center")
def command_center(hours: int = Query(24, ge=1, le=168)):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    recent_scans = list(
        col(C.SCANS)
        .find({"source": "github", "created_at": {"$gte": cutoff}})
        .sort("created_at", -1)
        .limit(50)
    )

    events = []
    for s in recent_scans:
        findings = s.get("findings") or []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            if sev in counts:
                counts[sev] += 1
        risk = int(s.get("risk_score") or 0)
        gate = "fail" if risk >= 70 else "pass"
        gh = s.get("github") or {}
        events.append(
            {
                "id": str(s["_id"]),
                "timestamp": _ts_utc(s["created_at"]).isoformat(),
                "event_type": "pr_scan",
                "repo": gh.get("repo_full_name"),
                "pr_number": gh.get("pr_number"),
                "risk_score": risk,
                "severity_counts": counts,
                "author": gh.get("author_login"),
                "gate_result": gate,
            }
        )

    return {
        "events": events,
        "anomalies": _detect_anomalies(cutoff),
        "ownership_routing": _build_ownership(cutoff),
        "sla_breaches": _check_sla_breaches(cutoff),
        "window_hours": hours,
        "total_scans": len(recent_scans),
        "gate_failures": sum(1 for e in events if e["gate_result"] == "fail"),
    }


def _detect_anomalies(cutoff: datetime) -> List[Dict]:
    """Compare recent risk per repo against its 14-day historical baseline."""
    baseline_cutoff = cutoff - timedelta(days=14)
    cur = col(C.SCANS).find(
        {"source": "github", "created_at": {"$gte": baseline_cutoff}}
    )

    repo_baseline: Dict[str, List[float]] = defaultdict(list)
    repo_recent: Dict[str, List[float]] = defaultdict(list)
    for s in cur:
        repo = (s.get("github") or {}).get("repo_full_name")
        if not repo:
            continue
        ts = _ts_utc(s["created_at"])
        score = float(s.get("risk_score") or 0)
        if ts >= cutoff:
            repo_recent[repo].append(score)
        else:
            repo_baseline[repo].append(score)

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
            anomalies.append(
                {
                    "repo": repo,
                    "metric": "avg_risk_score",
                    "current_value": round(avg_recent, 1),
                    "baseline_value": round(avg_baseline, 1),
                    "deviation_pct": round(deviation, 1),
                    "direction": "increasing" if deviation > 0 else "decreasing",
                }
            )
    return sorted(anomalies, key=lambda a: -abs(a["deviation_pct"]))


def _build_ownership(cutoff: datetime) -> List[Dict]:
    """Route findings to authors who need attention."""
    cur = col(C.SCANS).find(
        {
            "source": "github",
            "created_at": {"$gte": cutoff},
            "github.author_login": {"$ne": None},
        }
    )

    author_data: Dict[str, Dict] = defaultdict(
        lambda: {"critical_high": 0, "repos": set(), "risk_sum": 0.0, "count": 0}
    )
    for s in cur:
        gh = s.get("github") or {}
        author = gh.get("author_login")
        if not author:
            continue
        data = author_data[author]
        data["count"] += 1
        data["risk_sum"] += float(s.get("risk_score") or 0)
        if gh.get("repo_full_name"):
            data["repos"].add(gh["repo_full_name"])
        for f in s.get("findings") or []:
            sev = (f.get("severity") or "low").lower()
            if sev in ("critical", "high"):
                data["critical_high"] += 1

    ownership = []
    for author, data in author_data.items():
        avg_risk = data["risk_sum"] / max(1, data["count"])
        ownership.append(
            {
                "author": author,
                "open_critical_high": data["critical_high"],
                "repos": sorted(data["repos"]),
                "avg_risk": round(avg_risk, 1),
                "needs_attention": data["critical_high"] > 0 or avg_risk >= 60,
            }
        )
    return sorted(ownership, key=lambda o: -o["open_critical_high"])


def _check_sla_breaches(cutoff: datetime) -> List[Dict]:
    """Stale repos and unresolved high-risk PRs."""
    breaches: List[Dict] = []

    recent_scans = list(
        col(C.SCANS).find({"source": "github", "created_at": {"$gte": cutoff}})
    )
    repo_last_scan: Dict[str, datetime] = {}
    for s in recent_scans:
        repo = (s.get("github") or {}).get("repo_full_name")
        if not repo:
            continue
        ts = _ts_utc(s["created_at"])
        if repo not in repo_last_scan or ts > repo_last_scan[repo]:
            repo_last_scan[repo] = ts

    all_repos = col(C.SCANS).distinct(
        "github.repo_full_name",
        {"source": "github", "github.repo_full_name": {"$ne": None}},
    )
    for repo in all_repos:
        if repo and repo not in repo_last_scan:
            breaches.append(
                {
                    "type": "stale_repo",
                    "repo": repo,
                    "detail": "No scans in monitoring window",
                    "severity": "warning",
                }
            )

    high_risk = col(C.SCANS).find(
        {
            "source": "github",
            "risk_score": {"$gte": 70},
            "created_at": {"$gte": cutoff},
        }
    )
    now = datetime.now(timezone.utc)
    for s in high_risk:
        ts = _ts_utc(s["created_at"])
        hours_open = (now - ts).total_seconds() / 3600
        if hours_open > 24:
            score = int(s.get("risk_score") or 0)
            gh = s.get("github") or {}
            breaches.append(
                {
                    "type": "unresolved_high_risk",
                    "repo": gh.get("repo_full_name"),
                    "pr_number": gh.get("pr_number"),
                    "risk_score": score,
                    "hours_open": round(hours_open, 1),
                    "detail": f"PR #{gh.get('pr_number')} has risk score {score} open for {round(hours_open)}h",
                    "severity": "critical" if score >= 85 else "high",
                }
            )

    return sorted(breaches, key=lambda b: 0 if b["severity"] == "critical" else 1)
