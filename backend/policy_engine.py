"""Enhanced policy engine: versioned rules, simulation, and explanation trails.

v0.4: Mongo-backed. Versions are stored in `policy_versions`. The legacy `db`
parameter is accepted (and ignored) so existing call sites don't have to be
updated all at once.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import repositories as repos
from mongo import C, col
from policy import PolicyError, apply_policy, parse_policy  # noqa: F401  (re-exported)


def _next_version(repo_full_name: Optional[str], org_id: Optional[str]) -> int:
    latest = (
        col(C.POLICY_VERSIONS)
        .find({"repo_full_name": repo_full_name, "org_id": org_id})
        .sort("version", -1)
        .limit(1)
    )
    doc = next(iter(latest), None)
    return int(doc.get("version", 0)) + 1 if doc else 1


def _deactivate_active(repo_full_name: Optional[str], org_id: Optional[str]) -> None:
    col(C.POLICY_VERSIONS).update_many(
        {"repo_full_name": repo_full_name, "org_id": org_id, "is_active": True},
        {"$set": {"is_active": False}},
    )


def save_policy_version(
    db: Any,  # legacy compatibility — ignored
    yaml_text: str,
    repo_full_name: Optional[str] = None,
    org_id: Optional[Any] = None,
    author_id: Optional[Any] = None,
    change_summary: Optional[str] = None,
) -> Dict:
    """Validate and save a new policy version. Deactivates the previous active version."""
    policy, warnings = parse_policy(yaml_text)
    org_id_s = str(org_id) if org_id is not None else None

    _deactivate_active(repo_full_name, org_id_s)

    next_version = _next_version(repo_full_name, org_id_s)
    doc = {
        "org_id": org_id_s,
        "repo_full_name": repo_full_name,
        "version": next_version,
        "yaml_text": yaml_text,
        "author_id": str(author_id) if author_id is not None else None,
        "change_summary": change_summary,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }
    res = col(C.POLICY_VERSIONS).insert_one(doc)
    doc["_id"] = res.inserted_id

    return {
        "id": str(doc["_id"]),
        "version": next_version,
        "created_at": doc["created_at"].isoformat(),
        "warnings": warnings,
        "policy": policy,
    }


def get_active_policy(
    db: Any,  # legacy compatibility — ignored
    repo_full_name: Optional[str] = None,
    org_id: Optional[Any] = None,
) -> Optional[Dict]:
    """Fetch the current active policy for a repo/org."""
    org_id_s = str(org_id) if org_id is not None else None
    pv = col(C.POLICY_VERSIONS).find_one(
        {"repo_full_name": repo_full_name, "org_id": org_id_s, "is_active": True}
    )
    if not pv:
        return None
    policy, _ = parse_policy(pv["yaml_text"])
    created = pv.get("created_at") or datetime.now(timezone.utc)
    if hasattr(created, "isoformat"):
        created_iso = created.isoformat()
    else:
        created_iso = str(created)
    return {
        "id": str(pv["_id"]),
        "version": int(pv.get("version") or 1),
        "yaml_text": pv["yaml_text"],
        "policy": policy,
        "created_at": created_iso,
    }


def list_policy_versions(
    db: Any,  # legacy compatibility — ignored
    repo_full_name: Optional[str] = None,
    org_id: Optional[Any] = None,
    limit: int = 20,
) -> List[Dict]:
    """Return policy version history."""
    org_id_s = str(org_id) if org_id is not None else None
    cursor = (
        col(C.POLICY_VERSIONS)
        .find({"repo_full_name": repo_full_name, "org_id": org_id_s})
        .sort("version", -1)
        .limit(limit)
    )
    out: list[dict] = []
    for pv in cursor:
        created = pv.get("created_at") or datetime.now(timezone.utc)
        out.append(
            {
                "id": str(pv["_id"]),
                "version": int(pv.get("version") or 1),
                "is_active": bool(pv.get("is_active", False)),
                "change_summary": pv.get("change_summary"),
                "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
            }
        )
    return out


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
