"""Product-manager dashboard — Mongo-backed (v0.4 port).

All figures come from real `scans` documents (source='github'). The
remediation_delta is the wall-clock gap between the first failing scan and
the first subsequent passing scan on the same `(repo_full_name, pr_number)`.
If a PR never crossed back under the gate, the delta is null.
"""
from __future__ import annotations

from collections import defaultdict
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from auth import require_role
from config import settings
from mongo import C, col


router = APIRouter(prefix="/api/dashboard", tags=["pm"])


class AuthorStat(BaseModel):
    author_login: str
    scan_count: int
    avg_risk: float
    gate_failures: int
    last_scan_at: Optional[str] = None


class BlockedPR(BaseModel):
    scan_id: str
    repo_full_name: Optional[str] = None
    pr_number: Optional[int] = None
    pr_title: Optional[str] = None
    pr_url: Optional[str] = None
    commit_sha: Optional[str] = None
    risk_score: int
    author_login: Optional[str] = None
    created_at: str


class RemediationDelta(BaseModel):
    repo_full_name: str
    pr_number: int
    first_failing_at: str
    first_passing_at: Optional[str] = None
    delta_seconds: Optional[int] = None
    author_login: Optional[str] = None


class RepoHealth(BaseModel):
    repo_full_name: str
    scan_count: int
    avg_risk: float
    gate_failures: int


class PMDashboardResponse(BaseModel):
    by_author: List[AuthorStat]
    blocked_prs: List[BlockedPR]
    remediation_deltas: List[RemediationDelta]
    repo_health: List[RepoHealth]
    gate_threshold: int


def _by_author(threshold: int) -> List[AuthorStat]:
    pipeline = [
        {"$match": {"source": "github", "github.author_login": {"$ne": None}}},
        {
            "$group": {
                "_id": "$github.author_login",
                "scan_count": {"$sum": 1},
                "avg_risk": {"$avg": "$risk_score"},
                "gate_failures": {
                    "$sum": {"$cond": [{"$gte": ["$risk_score", threshold]}, 1, 0]}
                },
                "last_scan_at": {"$max": "$created_at"},
            }
        },
        {"$sort": {"gate_failures": -1, "avg_risk": -1}},
    ]
    out: List[AuthorStat] = []
    for r in col(C.SCANS).aggregate(pipeline):
        out.append(
            AuthorStat(
                author_login=r["_id"],
                scan_count=int(r["scan_count"]),
                avg_risk=round(float(r["avg_risk"] or 0), 1),
                gate_failures=int(r["gate_failures"]),
                last_scan_at=r["last_scan_at"].isoformat() if r.get("last_scan_at") else None,
            )
        )
    return out


def _blocked_prs(threshold: int, limit: int) -> List[BlockedPR]:
    cur = (
        col(C.SCANS)
        .find({"source": "github", "risk_score": {"$gte": threshold}})
        .sort("created_at", -1)
        .limit(limit)
    )
    out: List[BlockedPR] = []
    for s in cur:
        gh = s.get("github") or {}
        out.append(
            BlockedPR(
                scan_id=str(s["_id"]),
                repo_full_name=gh.get("repo_full_name"),
                pr_number=gh.get("pr_number"),
                pr_title=gh.get("pr_title"),
                pr_url=gh.get("pr_url"),
                commit_sha=gh.get("commit_sha"),
                risk_score=int(s.get("risk_score") or 0),
                author_login=gh.get("author_login"),
                created_at=s["created_at"].isoformat(),
            )
        )
    return out


def _remediation_deltas(threshold: int) -> List[RemediationDelta]:
    """Per (repo, pr): time between first failing scan and first subsequent passing scan."""
    cur = col(C.SCANS).find(
        {
            "source": "github",
            "github.repo_full_name": {"$ne": None},
            "github.pr_number": {"$ne": None},
        }
    ).sort("created_at", 1)

    by_pr: dict = defaultdict(list)
    for s in cur:
        gh = s.get("github") or {}
        by_pr[(gh.get("repo_full_name"), gh.get("pr_number"))].append(s)

    out: List[RemediationDelta] = []
    for (repo, pr), scans in by_pr.items():
        first_fail = next(
            (s for s in scans if (s.get("risk_score") or 0) >= threshold), None
        )
        if not first_fail:
            continue
        first_pass = next(
            (
                s
                for s in scans
                if s["created_at"] >= first_fail["created_at"]
                and (s.get("risk_score") or 0) < threshold
            ),
            None,
        )
        delta = (
            int((first_pass["created_at"] - first_fail["created_at"]).total_seconds())
            if first_pass
            else None
        )
        out.append(
            RemediationDelta(
                repo_full_name=repo,
                pr_number=pr,
                first_failing_at=first_fail["created_at"].isoformat(),
                first_passing_at=first_pass["created_at"].isoformat()
                if first_pass
                else None,
                delta_seconds=delta,
                author_login=(first_fail.get("github") or {}).get("author_login"),
            )
        )
    out.sort(key=lambda x: x.first_failing_at, reverse=True)
    return out


def _repo_health(threshold: int) -> List[RepoHealth]:
    pipeline = [
        {"$match": {"source": "github", "github.repo_full_name": {"$ne": None}}},
        {
            "$group": {
                "_id": "$github.repo_full_name",
                "scan_count": {"$sum": 1},
                "avg_risk": {"$avg": "$risk_score"},
                "gate_failures": {
                    "$sum": {"$cond": [{"$gte": ["$risk_score", threshold]}, 1, 0]}
                },
            }
        },
    ]
    out: List[RepoHealth] = []
    for r in col(C.SCANS).aggregate(pipeline):
        out.append(
            RepoHealth(
                repo_full_name=r["_id"],
                scan_count=int(r["scan_count"]),
                avg_risk=round(float(r["avg_risk"] or 0), 1),
                gate_failures=int(r["gate_failures"]),
            )
        )
    out.sort(key=lambda r: -(r.scan_count * r.avg_risk))
    return out


@router.get(
    "/pm",
    response_model=PMDashboardResponse,
    dependencies=[Depends(require_role("pm", "admin"))],
)
def pm_dashboard(blocked_limit: int = Query(25, ge=1, le=100)):
    threshold = settings.RISK_GATE_THRESHOLD
    return PMDashboardResponse(
        by_author=_by_author(threshold),
        blocked_prs=_blocked_prs(threshold, blocked_limit),
        remediation_deltas=_remediation_deltas(threshold),
        repo_health=_repo_health(threshold),
        gate_threshold=threshold,
    )
