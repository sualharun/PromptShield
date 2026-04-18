"""Baseline suppression and drift detection — Mongo-backed (v0.4 port).

"Only show new regressions" per repo/team. Tracks which findings are known
(baseline) vs new since last scan. Enables teams to focus on regressions
rather than re-triaging the entire backlog.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

import repositories as repos
from suppression import finding_signature as compute_signature


def get_baseline_signatures(_db_unused: Any = None, repo: str = "") -> Set[str]:
    """Return all known baseline finding signatures for a repo."""
    return repos.baseline_signatures_for(repo)


def classify_findings(
    _db_unused: Any,
    repo: str,
    findings: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """Split findings into (new_regressions, known_baseline).

    New regressions are findings whose signature doesn't exist in the baseline.
    Known baseline findings get a 'baseline': True annotation.
    """
    baseline_sigs = repos.baseline_signatures_for(repo)
    new_findings: List[Dict] = []
    known_findings: List[Dict] = []

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
    _db_unused: Any,
    repo: str,
    findings: List[Dict],
    org_id: Optional[Any] = None,
) -> Dict:
    """Upsert findings into the baseline for a repo. Returns add/update stats."""
    added = 0
    updated = 0
    for f in findings:
        sig = compute_signature(f)
        was_new = repos.upsert_baseline(
            repo=repo,
            signature=sig,
            finding_type=str(f.get("type") or "UNKNOWN"),
            severity=str(f.get("severity") or "low"),
            org_id=org_id,
        )
        if was_new:
            added += 1
        else:
            updated += 1
    total = len(repos.baseline_signatures_for(repo))
    return {"added": added, "updated": updated, "total_baseline": total}


def acknowledge_baseline(
    _db_unused: Any,
    repo: str,
    signature: str,
    acknowledged_by: str,
) -> bool:
    """Mark a baseline finding as acknowledged (triaged)."""
    return repos.acknowledge_baseline(repo=repo, signature=signature, by=acknowledged_by)


def get_drift_summary(_db_unused: Any = None, repo: str = "") -> Dict:
    """Summary of baseline health for a repo."""
    return repos.baseline_summary(repo)


def get_regressions_only(
    _db_unused: Any,
    repo: str,
    findings: List[Dict],
) -> List[Dict]:
    """Filter to only findings that are NOT in the baseline — true regressions."""
    new, _ = classify_findings(None, repo, findings)
    return new
