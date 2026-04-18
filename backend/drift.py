"""Baseline suppression and drift detection.

"Only show new regressions" per repo/team. Tracks which findings are known
(baseline) vs new since last scan. Enables teams to focus on regressions
rather than re-triaging the entire backlog.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from models import BaselineFinding
from suppression import finding_signature as compute_signature


def get_baseline_signatures(db: Session, repo: str) -> Set[str]:
    """Return all known baseline finding signatures for a repo."""
    rows = (
        db.query(BaselineFinding.signature)
        .filter(BaselineFinding.repo_full_name == repo)
        .all()
    )
    return {r[0] for r in rows}


def classify_findings(
    db: Session,
    repo: str,
    findings: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """Split findings into (new_regressions, known_baseline).

    New regressions are findings whose signature doesn't exist in the baseline.
    Known baseline findings get a 'baseline': True annotation.
    """
    baseline_sigs = get_baseline_signatures(db, repo)
    new_findings = []
    known_findings = []

    for f in findings:
        sig = compute_signature(f)
        f["signature"] = sig
        if sig in baseline_sigs:
            f["baseline"] = True
            known_findings.append(f)
        else:
            f["baseline"] = False
            new_findings.append(f)

    return new_findings, known_findings


def update_baseline(
    db: Session,
    repo: str,
    findings: List[Dict],
    org_id: Optional[int] = None,
) -> Dict:
    """Upsert findings into the baseline for a repo.

    Called after each scan to track what's "known". Returns stats on
    new vs updated entries.
    """
    now = datetime.now(timezone.utc)
    existing_sigs = get_baseline_signatures(db, repo)
    added = 0
    updated = 0

    for f in findings:
        sig = compute_signature(f)
        if sig in existing_sigs:
            row = (
                db.query(BaselineFinding)
                .filter(
                    BaselineFinding.repo_full_name == repo,
                    BaselineFinding.signature == sig,
                )
                .first()
            )
            if row:
                row.last_seen_at = now
                updated += 1
        else:
            db.add(BaselineFinding(
                repo_full_name=repo,
                org_id=org_id,
                signature=sig,
                finding_type=f.get("type", "UNKNOWN"),
                severity=(f.get("severity") or "low").lower(),
                first_seen_at=now,
                last_seen_at=now,
            ))
            added += 1

    db.commit()
    return {"added": added, "updated": updated, "total_baseline": len(existing_sigs) + added}


def acknowledge_baseline(
    db: Session,
    repo: str,
    signature: str,
    acknowledged_by: str,
) -> bool:
    """Mark a baseline finding as acknowledged (triaged)."""
    row = (
        db.query(BaselineFinding)
        .filter(
            BaselineFinding.repo_full_name == repo,
            BaselineFinding.signature == signature,
        )
        .first()
    )
    if not row:
        return False
    row.acknowledged = True
    row.acknowledged_by = acknowledged_by
    db.commit()
    return True


def get_drift_summary(db: Session, repo: str) -> Dict:
    """Summary of baseline health for a repo."""
    rows = (
        db.query(BaselineFinding)
        .filter(BaselineFinding.repo_full_name == repo)
        .all()
    )
    total = len(rows)
    acknowledged = sum(1 for r in rows if r.acknowledged)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        sev = r.severity.lower()
        if sev in by_severity:
            by_severity[sev] += 1
    return {
        "repo": repo,
        "total_baseline": total,
        "acknowledged": acknowledged,
        "unacknowledged": total - acknowledged,
        "by_severity": by_severity,
    }


def get_regressions_only(
    db: Session,
    repo: str,
    findings: List[Dict],
) -> List[Dict]:
    """Filter to only findings that are NOT in the baseline — true regressions."""
    new, _ = classify_findings(db, repo, findings)
    return new
