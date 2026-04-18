"""Product-manager dashboard: aggregates over GitHub scans by author and repo.

All figures come from real rows in the `scans` table. We don't fabricate a
time-to-fix: `remediation_deltas` is the wall-clock gap between the first
failing scan and the first subsequent passing scan on the same (repo, pr_number).
If a PR never crossed back under the gate, the delta is null.
"""

from collections import defaultdict
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from auth import require_role
from config import settings
from database import Scan, get_db


router = APIRouter(prefix="/api/dashboard", tags=["pm"])


class AuthorStat(BaseModel):
    author_login: str
    scan_count: int
    avg_risk: float
    gate_failures: int
    last_scan_at: Optional[str] = None


class BlockedPR(BaseModel):
    scan_id: int
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


def _by_author(db: Session, threshold: int) -> List[AuthorStat]:
    rows = (
        db.query(Scan)
        .filter(Scan.source == "github")
        .filter(Scan.author_login.isnot(None))
        .all()
    )
    agg: dict = defaultdict(
        lambda: {"scan_count": 0, "risk_sum": 0.0, "gate_failures": 0, "last": None}
    )
    for s in rows:
        a = agg[s.author_login]
        a["scan_count"] += 1
        a["risk_sum"] += float(s.risk_score or 0)
        if (s.risk_score or 0) >= threshold:
            a["gate_failures"] += 1
        if a["last"] is None or s.created_at > a["last"]:
            a["last"] = s.created_at
    out = [
        AuthorStat(
            author_login=login,
            scan_count=v["scan_count"],
            avg_risk=round(v["risk_sum"] / max(1, v["scan_count"]), 1),
            gate_failures=v["gate_failures"],
            last_scan_at=v["last"].isoformat() if v["last"] else None,
        )
        for login, v in agg.items()
    ]
    out.sort(key=lambda x: (-x.gate_failures, -x.avg_risk))
    return out


def _blocked_prs(db: Session, threshold: int, limit: int) -> List[BlockedPR]:
    rows = (
        db.query(Scan)
        .filter(Scan.source == "github")
        .filter(Scan.risk_score >= threshold)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        BlockedPR(
            scan_id=s.id,
            repo_full_name=s.repo_full_name,
            pr_number=s.pr_number,
            pr_title=s.pr_title,
            pr_url=s.pr_url,
            commit_sha=s.commit_sha,
            risk_score=int(s.risk_score or 0),
            author_login=s.author_login,
            created_at=s.created_at.isoformat(),
        )
        for s in rows
    ]


def _remediation_deltas(db: Session, threshold: int) -> List[RemediationDelta]:
    """Per (repo, pr): time between first failing scan and first subsequent passing scan."""
    rows = (
        db.query(Scan)
        .filter(Scan.source == "github")
        .filter(Scan.repo_full_name.isnot(None))
        .filter(Scan.pr_number.isnot(None))
        .order_by(Scan.created_at.asc())
        .all()
    )
    by_pr: dict = defaultdict(list)
    for s in rows:
        by_pr[(s.repo_full_name, s.pr_number)].append(s)

    out: List[RemediationDelta] = []
    for (repo, pr), scans in by_pr.items():
        first_fail = next(
            (s for s in scans if (s.risk_score or 0) >= threshold), None
        )
        if not first_fail:
            continue
        first_pass = next(
            (
                s
                for s in scans
                if s.created_at >= first_fail.created_at
                and (s.risk_score or 0) < threshold
            ),
            None,
        )
        delta = (
            int((first_pass.created_at - first_fail.created_at).total_seconds())
            if first_pass
            else None
        )
        out.append(
            RemediationDelta(
                repo_full_name=repo,
                pr_number=pr,
                first_failing_at=first_fail.created_at.isoformat(),
                first_passing_at=first_pass.created_at.isoformat()
                if first_pass
                else None,
                delta_seconds=delta,
                author_login=first_fail.author_login,
            )
        )
    out.sort(key=lambda x: x.first_failing_at, reverse=True)
    return out


def _repo_health(db: Session, threshold: int) -> List[RepoHealth]:
    rows = (
        db.query(
            Scan.repo_full_name,
            func.count(Scan.id),
            func.avg(Scan.risk_score),
        )
        .filter(Scan.source == "github")
        .filter(Scan.repo_full_name.isnot(None))
        .group_by(Scan.repo_full_name)
        .all()
    )
    fails_by_repo: dict = defaultdict(int)
    for s in (
        db.query(Scan.repo_full_name)
        .filter(Scan.source == "github")
        .filter(Scan.risk_score >= threshold)
        .all()
    ):
        if s[0]:
            fails_by_repo[s[0]] += 1

    out = [
        RepoHealth(
            repo_full_name=repo,
            scan_count=int(count),
            avg_risk=round(float(avg_risk or 0), 1),
            gate_failures=fails_by_repo.get(repo, 0),
        )
        for (repo, count, avg_risk) in rows
    ]
    out.sort(key=lambda r: -(r.scan_count * r.avg_risk))
    return out


@router.get(
    "/pm",
    response_model=PMDashboardResponse,
    dependencies=[Depends(require_role("pm", "admin"))],
)
def pm_dashboard(
    db: Session = Depends(get_db),
    blocked_limit: int = Query(25, ge=1, le=100),
):
    threshold = settings.RISK_GATE_THRESHOLD
    return PMDashboardResponse(
        by_author=_by_author(db, threshold),
        blocked_prs=_blocked_prs(db, threshold, blocked_limit),
        remediation_deltas=_remediation_deltas(db, threshold),
        repo_health=_repo_health(db, threshold),
        gate_threshold=threshold,
    )
