"""Enhanced policy engine: versioned rules, simulation, and explanation trails.

Wraps the existing policy.py with versioning (stored in policy_versions table)
and adds a rule simulator that explains why each rule fired.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from models import PolicyVersion
from policy import PolicyError, apply_policy, parse_policy


def save_policy_version(
    db: Session,
    yaml_text: str,
    repo_full_name: Optional[str] = None,
    org_id: Optional[int] = None,
    author_id: Optional[int] = None,
    change_summary: Optional[str] = None,
) -> Dict:
    """Validate and save a new policy version. Deactivates the previous active version."""
    policy, warnings = parse_policy(yaml_text)

    current = (
        db.query(PolicyVersion)
        .filter(
            PolicyVersion.repo_full_name == repo_full_name,
            PolicyVersion.org_id == org_id,
            PolicyVersion.is_active == True,
        )
        .first()
    )
    next_version = (current.version + 1) if current else 1
    if current:
        current.is_active = False

    pv = PolicyVersion(
        org_id=org_id,
        repo_full_name=repo_full_name,
        version=next_version,
        yaml_text=yaml_text,
        author_id=author_id,
        change_summary=change_summary,
    )
    db.add(pv)
    db.commit()
    db.refresh(pv)

    return {
        "id": pv.id,
        "version": pv.version,
        "created_at": pv.created_at.isoformat(),
        "warnings": warnings,
        "policy": policy,
    }


def get_active_policy(
    db: Session,
    repo_full_name: Optional[str] = None,
    org_id: Optional[int] = None,
) -> Optional[Dict]:
    """Fetch the current active policy for a repo/org."""
    pv = (
        db.query(PolicyVersion)
        .filter(
            PolicyVersion.repo_full_name == repo_full_name,
            PolicyVersion.org_id == org_id,
            PolicyVersion.is_active == True,
        )
        .first()
    )
    if not pv:
        return None
    policy, _ = parse_policy(pv.yaml_text)
    return {
        "id": pv.id,
        "version": pv.version,
        "yaml_text": pv.yaml_text,
        "policy": policy,
        "created_at": pv.created_at.isoformat(),
    }


def list_policy_versions(
    db: Session,
    repo_full_name: Optional[str] = None,
    org_id: Optional[int] = None,
    limit: int = 20,
) -> List[Dict]:
    """Return policy version history."""
    q = db.query(PolicyVersion).filter(
        PolicyVersion.repo_full_name == repo_full_name,
        PolicyVersion.org_id == org_id,
    ).order_by(PolicyVersion.version.desc()).limit(limit)

    return [
        {
            "id": pv.id,
            "version": pv.version,
            "is_active": pv.is_active,
            "change_summary": pv.change_summary,
            "created_at": pv.created_at.isoformat(),
        }
        for pv in q.all()
    ]


def simulate_policy(
    yaml_text: str,
    findings: List[Dict],
    risk_score: int,
) -> Dict:
    """Run policy against findings and produce an explanation trail.

    Returns the decision plus a per-rule trace showing which rules fired,
    which findings were affected, and why.
    """
    policy, warnings = parse_policy(yaml_text)
    decision = apply_policy(policy, findings, risk_score)

    explanation_trail = []

    min_score = policy.get("min_score")
    if min_score is not None:
        fired = decision["effective_score"] >= min_score
        explanation_trail.append({
            "rule": "min_score",
            "config": min_score,
            "fired": fired,
            "reason": (
                f"Effective score {decision['effective_score']} {'≥' if fired else '<'} threshold {min_score}"
            ),
        })

    block_if = policy.get("block_if", {})
    for sev, threshold in block_if.items():
        count = decision["counts"].get(sev, 0)
        fired = count >= threshold
        explanation_trail.append({
            "rule": f"block_if.{sev}",
            "config": threshold,
            "actual": count,
            "fired": fired,
            "reason": f"Found {count} {sev} finding(s), threshold is {threshold}",
        })

    ignore_cfg = policy.get("ignore", {})
    ignored_types = ignore_cfg.get("types", [])
    ignored_cwes = ignore_cfg.get("cwes", [])
    if ignored_types:
        dropped = [f for f in findings if f.get("type") in ignored_types]
        explanation_trail.append({
            "rule": "ignore.types",
            "config": ignored_types,
            "dropped_count": len(dropped),
            "fired": len(dropped) > 0,
            "reason": f"Dropped {len(dropped)} finding(s) matching types {ignored_types}",
        })
    if ignored_cwes:
        dropped = [f for f in findings if f.get("cwe") in ignored_cwes]
        explanation_trail.append({
            "rule": "ignore.cwes",
            "config": ignored_cwes,
            "dropped_count": len(dropped),
            "fired": len(dropped) > 0,
            "reason": f"Dropped {len(dropped)} finding(s) matching CWEs {ignored_cwes}",
        })

    overrides = policy.get("severity_overrides", {})
    for ftype, new_sev in overrides.items():
        affected = [f for f in findings if f.get("type") == ftype]
        explanation_trail.append({
            "rule": f"severity_overrides.{ftype}",
            "config": new_sev,
            "affected_count": len(affected),
            "fired": len(affected) > 0,
            "reason": f"Rewrote {len(affected)} {ftype} finding(s) to severity={new_sev}",
        })

    return {
        "decision": decision,
        "explanation_trail": explanation_trail,
        "warnings": warnings,
        "policy": policy,
    }


def diff_policies(yaml_old: str, yaml_new: str) -> Dict:
    """Compare two policy versions and describe changes."""
    old_policy, _ = parse_policy(yaml_old)
    new_policy, _ = parse_policy(yaml_new)

    changes = []
    all_keys = set(list(old_policy.keys()) + list(new_policy.keys()))
    for key in sorted(all_keys):
        old_val = old_policy.get(key)
        new_val = new_policy.get(key)
        if old_val != new_val:
            changes.append({
                "field": key,
                "old": old_val,
                "new": new_val,
                "change_type": (
                    "added" if old_val is None
                    else "removed" if new_val is None
                    else "modified"
                ),
            })

    return {
        "changes": changes,
        "has_changes": len(changes) > 0,
    }
