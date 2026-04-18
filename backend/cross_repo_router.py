"""Cross-repo intelligence: finding types that recur across multiple repos,
and vulnerability-type trends over a rolling 30-day window.

Data is aggregated from real `scans` rows (source='github'). Time buckets are
UTC day strings so frontend charts can plot them without timezone math.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Scan, get_db


router = APIRouter(prefix="/api/dashboard", tags=["cross-repo"])


class RepoOccurrence(BaseModel):
    repo_full_name: str
    count: int


class CrossRepoFinding(BaseModel):
    finding_type: str
    repo_count: int
    total_count: int
    severity: str
    repos: List[RepoOccurrence]


class TrendPoint(BaseModel):
    date: str
    finding_type: str
    count: int


class CrossRepoResponse(BaseModel):
    recurring: List[CrossRepoFinding]
    trending: List[TrendPoint]
    top_types_last_30d: List[str]
    window_days: int


def _severity_rank(sev: str) -> int:
    return {"critical": 3, "high": 2, "medium": 1, "low": 0}.get((sev or "").lower(), 0)


@router.get("/cross-repo", response_model=CrossRepoResponse)
def cross_repo(
    db: Session = Depends(get_db),
    min_repos: int = Query(2, ge=1, le=20),
    window_days: int = Query(30, ge=7, le=180),
    top_n: int = Query(5, ge=1, le=20),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    rows = (
        db.query(Scan)
        .filter(Scan.source == "github")
        .filter(Scan.repo_full_name.isnot(None))
        .filter(Scan.created_at >= cutoff.replace(tzinfo=None))
        .all()
    )

    # repos-per-type + severity + total occurrences
    per_type_repos: Dict[str, Counter] = defaultdict(Counter)
    per_type_severity: Dict[str, str] = {}
    per_type_total: Counter = Counter()

    # daily series per finding type
    daily: Dict[tuple, int] = defaultdict(int)

    for s in rows:
        repo = s.repo_full_name
        day = s.created_at.date().isoformat()
        try:
            findings = json.loads(s.findings_json or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        for f in findings:
            ftype = f.get("type")
            if not ftype:
                continue
            per_type_repos[ftype][repo] += 1
            per_type_total[ftype] += 1
            current = per_type_severity.get(ftype, "")
            if _severity_rank(f.get("severity", "low")) > _severity_rank(current):
                per_type_severity[ftype] = (f.get("severity") or "low").lower()
            daily[(day, ftype)] += 1

    recurring: List[CrossRepoFinding] = []
    for ftype, repos in per_type_repos.items():
        if len(repos) < min_repos:
            continue
        recurring.append(
            CrossRepoFinding(
                finding_type=ftype,
                repo_count=len(repos),
                total_count=per_type_total[ftype],
                severity=per_type_severity.get(ftype, "low"),
                repos=[
                    RepoOccurrence(repo_full_name=r, count=c)
                    for r, c in repos.most_common()
                ],
            )
        )
    recurring.sort(
        key=lambda x: (-_severity_rank(x.severity), -x.repo_count, -x.total_count)
    )

    top_types = [t for t, _ in per_type_total.most_common(top_n)]
    trending = [
        TrendPoint(date=day, finding_type=ftype, count=count)
        for (day, ftype), count in daily.items()
        if ftype in top_types
    ]
    trending.sort(key=lambda p: (p.date, p.finding_type))

    return CrossRepoResponse(
        recurring=recurring,
        trending=trending,
        top_types_last_30d=top_types,
        window_days=window_days,
    )
