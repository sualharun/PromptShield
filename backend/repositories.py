"""Thin repository layer over the Mongo collections.

Routes call repository functions, never `col(...)` directly. This:

  • centralizes ObjectId <-> str conversion (a Mongo-specific gotcha that
    would otherwise leak into every router)
  • lets us swap in mongomock for tests without route code knowing
  • makes aggregation pipelines reusable (the dashboard, the PM view, and the
    cross-repo view all want the same group_by under the hood)

Each `*_to_view` helper produces a JSON-safe dict shaped like the original
API responses, so FastAPI models stay stable across the Mongo cutover.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from bson import ObjectId
from pymongo import DESCENDING

from mongo import C, col

logger = logging.getLogger("promptshield.repos")


# ── Object id helpers ───────────────────────────────────────────────────────
def _oid(value: Any) -> Optional[ObjectId]:
    """Coerce str/int/ObjectId -> ObjectId, return None if invalid/missing.

    Legacy code uses integer scan IDs everywhere. We accept both: integer ids
    are looked up via the `legacy_id` field that the migration script writes.
    """
    if value is None or value == "":
        return None
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except Exception:
        return None


def _is_int_id(value: Any) -> bool:
    if isinstance(value, int):
        return True
    if isinstance(value, str) and value.isdigit():
        return True
    return False


# ── Scan repo ───────────────────────────────────────────────────────────────
def scan_to_view(doc: dict) -> dict:
    """Project a Mongo scan doc into the dict shape the existing API returns.

    Mirrors the JSON contract the React frontend already expects, which means
    the frontend keeps working through the cutover.
    """
    if not doc:
        return {}
    github = doc.get("github") or {}
    counts = doc.get("counts") or {}
    view = {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "legacy_id": doc.get("legacy_id"),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
        "input_text": doc.get("input_text", ""),
        "risk_score": float(doc.get("risk_score", 0)),
        "findings": doc.get("findings", []),
        "static_count": int(counts.get("static", doc.get("static_count", 0))),
        "ai_count": int(counts.get("ai", doc.get("ai_count", 0))),
        "total_count": int(counts.get("total", doc.get("total_count", 0))),
        "source": doc.get("source", "web"),
        "repo_full_name": github.get("repo_full_name"),
        "pr_number": github.get("pr_number"),
        "commit_sha": github.get("commit_sha"),
        "pr_title": github.get("pr_title"),
        "pr_url": github.get("pr_url"),
        "author_login": github.get("author_login"),
        "llm_targets": ",".join(doc.get("llm_targets") or []) or None,
        "score_breakdown_json": json.dumps(doc.get("score_breakdown")) if doc.get("score_breakdown") else None,
        "graph_analysis_json": json.dumps(doc.get("graph_analysis")) if doc.get("graph_analysis") else None,
        "semantic_matches": doc.get("semantic_matches", []),
    }
    # Optional Atlas-search-only metadata: passed through when present so the
    # frontend can render fusion-score badges and search highlights without
    # extra round-trips.
    if "fusion_score" in doc:
        fs = doc["fusion_score"]
        try:
            view["fusion_score"] = float(fs) if isinstance(fs, (int, float)) else fs
        except Exception:
            view["fusion_score"] = fs
    if "score" in doc:
        try:
            view["search_score"] = float(doc["score"])
        except Exception:
            pass
    if "highlights" in doc:
        view["highlights"] = doc["highlights"]
    return view


def insert_scan(payload: dict) -> dict:
    """Insert a scan document. Returns the inserted document with `_id` set."""
    payload.setdefault("created_at", datetime.now(timezone.utc))
    payload.setdefault("source", "web")
    payload.setdefault("findings", [])
    payload.setdefault("counts", {"static": 0, "ai": 0, "total": 0})
    payload.setdefault("llm_targets", [])
    res = col(C.SCANS).insert_one(payload)
    payload["_id"] = res.inserted_id
    return payload


def get_scan(scan_id: Any) -> Optional[dict]:
    """Fetch by Mongo ObjectId *or* legacy integer id from the SQLite era."""
    oid = _oid(scan_id)
    if oid is not None:
        doc = col(C.SCANS).find_one({"_id": oid})
        if doc:
            return doc
    if _is_int_id(scan_id):
        return col(C.SCANS).find_one({"legacy_id": int(scan_id)})
    return None


def update_scan(scan_id: Any, fields: dict) -> bool:
    oid = _oid(scan_id)
    if oid is not None:
        return col(C.SCANS).update_one({"_id": oid}, {"$set": fields}).matched_count > 0
    if _is_int_id(scan_id):
        return col(C.SCANS).update_one({"legacy_id": int(scan_id)}, {"$set": fields}).matched_count > 0
    return False


def delete_scan(scan_id: Any) -> bool:
    oid = _oid(scan_id)
    q = {"_id": oid} if oid is not None else {"legacy_id": int(scan_id)} if _is_int_id(scan_id) else None
    if q is None:
        return False
    return col(C.SCANS).delete_one(q).deleted_count > 0


def list_scans(
    *,
    source: Optional[str] = None,
    repo: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
) -> list[dict]:
    q: dict = {}
    if source:
        q["source"] = source
    if repo:
        q["github.repo_full_name"] = repo
    cur = col(C.SCANS).find(q).sort("created_at", DESCENDING).skip(offset).limit(limit)
    return list(cur)


def count_scans(*, source: Optional[str] = None) -> int:
    q: dict = {}
    if source:
        q["source"] = source
    return col(C.SCANS).count_documents(q)


def scans_since(since: datetime, *, source: Optional[str] = None) -> list[dict]:
    q: dict = {"created_at": {"$gte": since}}
    if source:
        q["source"] = source
    return list(col(C.SCANS).find(q).sort("created_at", 1))


# ── Aggregations (repo / dashboard group-bys) ─────────────────────────────
def repo_aggregates(*, source: str = "github", limit: int = 10) -> list[dict]:
    """Replaces the func.count + func.avg + group_by in main.py:807."""
    pipeline = [
        {"$match": {"source": source, "github.repo_full_name": {"$ne": None}}},
        {
            "$group": {
                "_id": "$github.repo_full_name",
                "scan_count": {"$sum": 1},
                "avg_risk": {"$avg": "$risk_score"},
                "max_risk": {"$max": "$risk_score"},
            }
        },
        {"$sort": {"scan_count": -1}},
        {"$limit": limit},
    ]
    return list(col(C.SCANS).aggregate(pipeline))


def llm_target_distribution() -> list[dict]:
    """Top LLM providers by scan count (replaces enterprise_router.py:481)."""
    pipeline = [
        {"$match": {"llm_targets": {"$exists": True, "$ne": []}}},
        {"$unwind": "$llm_targets"},
        {"$group": {"_id": "$llm_targets", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return list(col(C.SCANS).aggregate(pipeline))


def top_cwes(*, days: int = 30, limit: int = 10) -> list[dict]:
    """One-line replacement for what would have been a 3-table join in SQL."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"created_at": {"$gte": since}}},
        {"$unwind": "$findings"},
        {"$match": {"findings.cwe": {"$exists": True, "$ne": None}}},
        {"$group": {"_id": "$findings.cwe", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    return list(col(C.SCANS).aggregate(pipeline))


# ── Audit log ───────────────────────────────────────────────────────────────
def insert_audit(payload: dict) -> None:
    payload.setdefault("created_at", datetime.now(timezone.utc))
    payload.setdefault("actor", "system")
    payload.setdefault("source", "web")
    payload.setdefault("details", {})
    col(C.AUDIT_LOGS).insert_one(payload)


def list_audit(
    *,
    source: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    q: dict = {}
    if source:
        q["source"] = source
    if action:
        q["action"] = action
    return list(col(C.AUDIT_LOGS).find(q).sort("created_at", DESCENDING).limit(limit))


def audit_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
        "actor": doc.get("actor", "system"),
        "action": doc.get("action", ""),
        "source": doc.get("source", "web"),
        "repo_full_name": doc.get("repo_full_name"),
        "pr_number": doc.get("pr_number"),
        "scan_id": doc.get("scan_id"),
        "details_json": json.dumps(doc.get("details") or {}),
        "client_ip": doc.get("client_ip"),
    }


# ── Risk snapshots (time-series) ────────────────────────────────────────────
def insert_snapshot(doc: dict) -> None:
    doc.setdefault("ts", datetime.now(timezone.utc))
    doc.setdefault("meta", {"source": doc.pop("source", "github")})
    col(C.RISK_SNAPSHOTS).insert_one(doc)


def snapshot_window(*, source: str = "github", days: int = 30) -> list[dict]:
    """Pulls snapshots and computes a 7-day moving average + WoW delta in one
    aggregation pipeline. This is the pipeline the README's risk timeline tab
    will consume."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline: list[dict] = [
        {"$match": {"meta.source": source, "ts": {"$gte": since}}},
        {"$sort": {"ts": 1}},
        {
            "$setWindowFields": {
                "partitionBy": "$meta.source",
                "sortBy": {"ts": 1},
                "output": {
                    "rolling_7d_avg": {
                        "$avg": "$risk_score",
                        "window": {"range": [-7, 0], "unit": "day"},
                    },
                    "wow_delta": {
                        "$subtract": [
                            "$risk_score",
                            {
                                "$avg": "$risk_score",
                            },
                        ]
                    },
                },
            }
        },
    ]
    try:
        return list(col(C.RISK_SNAPSHOTS).aggregate(pipeline))
    except Exception as e:
        # mongomock doesn't implement $setWindowFields — fall back to plain.
        logger.info("snapshot_window window fn unavailable (%s) — plain sort", e)
        return list(
            col(C.RISK_SNAPSHOTS)
            .find({"meta.source": source, "ts": {"$gte": since}})
            .sort("ts", 1)
        )


# ── Users / orgs ────────────────────────────────────────────────────────────
def find_user_by_email(email: str) -> Optional[dict]:
    return col(C.USERS).find_one({"email": email.lower().strip()})


def insert_user(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    doc.setdefault("role", "viewer")
    doc["email"] = doc["email"].lower().strip()
    res = col(C.USERS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def get_org_by_slug(slug: str) -> Optional[dict]:
    return col(C.ORGANIZATIONS).find_one({"slug": slug})


# ── Finding suppressions ────────────────────────────────────────────────────
def list_suppressions(*, repo: Optional[str] = None) -> list[dict]:
    q: dict = {}
    if repo:
        q["repo_full_name"] = repo
    return list(col(C.FINDING_SUPPRESSIONS).find(q).sort("created_at", DESCENDING))


def suppressed_signatures_set(repo: Optional[str] = None) -> set[str]:
    if repo:
        q: dict = {"$or": [{"repo_full_name": repo}, {"repo_full_name": None}]}
    else:
        # Global queries only see global suppressions (repo_full_name == None).
        q = {"repo_full_name": None}
    return {d["signature"] for d in col(C.FINDING_SUPPRESSIONS).find(q, {"signature": 1})}


def insert_suppression(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    doc.setdefault("suppressed_by", "anonymous")
    res = col(C.FINDING_SUPPRESSIONS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def delete_suppression(sid: Any) -> bool:
    oid = _oid(sid)
    q = {"_id": oid} if oid is not None else {"legacy_id": int(sid)} if _is_int_id(sid) else None
    if q is None:
        return False
    return col(C.FINDING_SUPPRESSIONS).delete_one(q).deleted_count > 0


# ── Benchmark runs (Atlas-unique angle: model-registry / eval history) ─────
def insert_benchmark_run(doc: dict) -> dict:
    doc.setdefault("ts", datetime.now(timezone.utc))
    res = col(C.BENCHMARK_RUNS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def recent_benchmark_runs(limit: int = 20) -> list[dict]:
    return list(col(C.BENCHMARK_RUNS).find().sort("ts", DESCENDING).limit(limit))


# ── Users (full Mongo port) ─────────────────────────────────────────────────
def get_user_by_id(user_id: Any) -> Optional[dict]:
    oid = _oid(user_id)
    if oid is not None:
        doc = col(C.USERS).find_one({"_id": oid})
        if doc:
            return doc
    if _is_int_id(user_id):
        return col(C.USERS).find_one({"legacy_id": int(user_id)})
    return None


def update_user(user_id: Any, fields: dict) -> bool:
    oid = _oid(user_id)
    q = {"_id": oid} if oid is not None else {"legacy_id": int(user_id)} if _is_int_id(user_id) else None
    if q is None:
        return False
    return col(C.USERS).update_one(q, {"$set": fields}).modified_count > 0


def count_users() -> int:
    return col(C.USERS).count_documents({})


def user_to_view(doc: dict) -> dict:
    if not doc:
        return {}
    return {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "legacy_id": doc.get("legacy_id"),
        "email": doc.get("email"),
        "name": doc.get("name"),
        "role": doc.get("role", "viewer"),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
    }


# ── Baseline findings (drift detection) ─────────────────────────────────────
def baseline_signatures_for(repo: str) -> set[str]:
    cur = col(C.BASELINE_FINDINGS).find(
        {"repo_full_name": repo}, {"signature": 1}
    )
    return {d["signature"] for d in cur}


def list_baseline(
    *,
    repo: str,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 200,
) -> list[dict]:
    q: dict = {"repo_full_name": repo}
    if severity:
        q["severity"] = severity.lower()
    if acknowledged is not None:
        q["acknowledged"] = acknowledged
    return list(
        col(C.BASELINE_FINDINGS).find(q).sort("last_seen_at", DESCENDING).limit(limit)
    )


def upsert_baseline(
    *,
    repo: str,
    signature: str,
    finding_type: str,
    severity: str,
    org_id: Optional[Any] = None,
) -> bool:
    """True if newly inserted; False if it already existed (last_seen_at is bumped)."""
    now = datetime.now(timezone.utc)
    res = col(C.BASELINE_FINDINGS).update_one(
        {"repo_full_name": repo, "signature": signature},
        {
            "$setOnInsert": {
                "repo_full_name": repo,
                "signature": signature,
                "first_seen_at": now,
                "finding_type": finding_type,
                "severity": (severity or "low").lower(),
                "org_id": org_id,
                "acknowledged": False,
                "acknowledged_by": None,
            },
            "$set": {"last_seen_at": now},
        },
        upsert=True,
    )
    return bool(res.upserted_id)


def acknowledge_baseline(*, repo: str, signature: str, by: str) -> bool:
    res = col(C.BASELINE_FINDINGS).update_one(
        {"repo_full_name": repo, "signature": signature},
        {"$set": {"acknowledged": True, "acknowledged_by": by}},
    )
    return res.matched_count > 0


def baseline_summary(repo: str) -> dict:
    rows = list(col(C.BASELINE_FINDINGS).find({"repo_full_name": repo}))
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    ack = 0
    for r in rows:
        s = (r.get("severity") or "low").lower()
        if s in by_sev:
            by_sev[s] += 1
        if r.get("acknowledged"):
            ack += 1
    total = len(rows)
    return {
        "repo": repo,
        "total_baseline": total,
        "acknowledged": ack,
        "unacknowledged": total - ack,
        "by_severity": by_sev,
    }


def baseline_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "signature": doc.get("signature"),
        "finding_type": doc.get("finding_type"),
        "severity": doc.get("severity"),
        "first_seen_at": (doc.get("first_seen_at") or datetime.now(timezone.utc)).isoformat(),
        "last_seen_at": (doc.get("last_seen_at") or datetime.now(timezone.utc)).isoformat(),
        "acknowledged": bool(doc.get("acknowledged")),
        "acknowledged_by": doc.get("acknowledged_by"),
    }


# ── Suppressions (richer view + upsert) ─────────────────────────────────────
def suppression_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "signature": doc.get("signature"),
        "finding_type": doc.get("finding_type"),
        "finding_title": doc.get("finding_title"),
        "repo_full_name": doc.get("repo_full_name"),
        "reason": doc.get("reason"),
        "suppressed_by": doc.get("suppressed_by", "anonymous"),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
    }


def upsert_suppression(
    *,
    signature: str,
    finding_type: str,
    finding_title: str,
    repo_full_name: Optional[str],
    reason: Optional[str],
    suppressed_by: str,
) -> dict:
    """Idempotent — same (signature, repo) always returns the same doc."""
    now = datetime.now(timezone.utc)
    res = col(C.FINDING_SUPPRESSIONS).find_one_and_update(
        {"signature": signature, "repo_full_name": repo_full_name},
        {
            "$setOnInsert": {
                "signature": signature,
                "finding_type": finding_type,
                "finding_title": finding_title[:255],
                "repo_full_name": repo_full_name,
                "reason": reason,
                "suppressed_by": suppressed_by,
                "created_at": now,
            }
        },
        upsert=True,
        return_document=True,  # type: ignore[arg-type]
    )
    if res is None:
        # Older mongomock builds return None on upsert; fall back to a find.
        res = col(C.FINDING_SUPPRESSIONS).find_one(
            {"signature": signature, "repo_full_name": repo_full_name}
        )
    return res or {}


# ── Audit log helpers (more views) ──────────────────────────────────────────
def audit_count(*, action: Optional[str] = None) -> int:
    q = {"action": action} if action else {}
    return col(C.AUDIT_LOGS).count_documents(q)


# ── Integration events ──────────────────────────────────────────────────────
def insert_integration_event(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    doc.setdefault("delivered", False)
    doc.setdefault("attempts", 0)
    res = col(C.INTEGRATION_EVENTS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def list_undelivered_events(limit: int = 50) -> list[dict]:
    return list(
        col(C.INTEGRATION_EVENTS)
        .find({"delivered": False})
        .sort("created_at", 1)
        .limit(limit)
    )


def mark_event_delivered(event_id: Any, *, target: Optional[str] = None) -> bool:
    oid = _oid(event_id)
    if oid is None:
        return False
    res = col(C.INTEGRATION_EVENTS).update_one(
        {"_id": oid},
        {
            "$set": {
                "delivered": True,
                "delivered_at": datetime.now(timezone.utc),
                "delivery_target": target,
            },
            "$inc": {"attempts": 1},
        },
    )
    return res.matched_count > 0


# ── Dependencies ────────────────────────────────────────────────────────────
def upsert_dependency(*, name: str, version: str, registry: str = "pypi", **fields) -> dict:
    res = col(C.DEPENDENCIES).find_one_and_update(
        {"name": name, "version": version, "registry": registry},
        {
            "$setOnInsert": {
                "name": name,
                "version": version,
                "registry": registry,
                "ecosystem": fields.get("ecosystem", "python"),
                "created_at": datetime.now(timezone.utc),
            },
            "$set": {
                k: v
                for k, v in fields.items()
                if k in {"risk_score", "cve_count"}
            },
        },
        upsert=True,
        return_document=True,  # type: ignore[arg-type]
    )
    if res is None:
        res = col(C.DEPENDENCIES).find_one(
            {"name": name, "version": version, "registry": registry}
        )
    return res or {}


def list_top_risk_dependencies(limit: int = 20) -> list[dict]:
    return list(
        col(C.DEPENDENCIES).find().sort("risk_score", DESCENDING).limit(limit)
    )


# ── Graph nodes/edges ───────────────────────────────────────────────────────
def upsert_graph_node(*, scan_id: Any, node_id: str, **fields) -> None:
    sid = _oid(scan_id) or scan_id
    col(C.GRAPH_NODES).update_one(
        {"scan_id": sid, "node_id": node_id},
        {"$set": {"scan_id": sid, "node_id": node_id, **fields}},
        upsert=True,
    )


def insert_graph_edge(doc: dict) -> None:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    col(C.GRAPH_EDGES).insert_one(doc)


def graph_for_scan(scan_id: Any) -> dict:
    sid = _oid(scan_id) or scan_id
    nodes = list(col(C.GRAPH_NODES).find({"scan_id": sid}))
    edges = list(col(C.GRAPH_EDGES).find({"scan_id": sid}))
    return {"nodes": nodes, "edges": edges}


# ── Eval / benchmark runs (legacy table parity) ─────────────────────────────
def insert_eval_run(doc: dict) -> dict:
    doc.setdefault("run_at", datetime.now(timezone.utc))
    res = col(C.EVAL_RUNS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def recent_eval_runs(limit: int = 20) -> list[dict]:
    return list(col(C.EVAL_RUNS).find().sort("run_at", DESCENDING).limit(limit))


# ── Finding records (full lifecycle, mirrors SQL FindingRecord) ─────────────
def list_finding_records(
    *,
    repo: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    q: dict = {}
    if repo:
        q["repo_full_name"] = repo
    if status:
        q["status"] = status
    return list(
        col(C.FINDING_RECORDS).find(q).sort("last_seen_at", DESCENDING).limit(limit)
    )


def get_finding_record(record_id: Any) -> Optional[dict]:
    oid = _oid(record_id)
    if oid is None:
        return None
    return col(C.FINDING_RECORDS).find_one({"_id": oid})


def update_finding_record(record_id: Any, fields: dict) -> bool:
    oid = _oid(record_id)
    if oid is None:
        return False
    return col(C.FINDING_RECORDS).update_one({"_id": oid}, {"$set": fields}).matched_count > 0


def find_finding_record(*, signature: str, repo_full_name: Optional[str]) -> Optional[dict]:
    return col(C.FINDING_RECORDS).find_one(
        {"signature": signature, "repo_full_name": repo_full_name}
    )


def insert_finding_record(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    res = col(C.FINDING_RECORDS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def list_finding_records_filtered(
    *,
    status: Optional[str] = None,
    repo: Optional[str] = None,
    severity: Optional[str] = None,
    owner: Optional[str] = None,
    active_only: bool = True,
    limit: int = 200,
) -> list[dict]:
    q: dict = {}
    if status:
        q["status"] = status
    if repo:
        q["repo_full_name"] = repo
    if severity:
        q["severity"] = severity
    if owner:
        q["owner"] = owner
    if active_only:
        q["is_active"] = True
    return list(
        col(C.FINDING_RECORDS).find(q).sort("last_seen_at", DESCENDING).limit(limit)
    )


def list_active_finding_records_for_repo(repo: str) -> list[dict]:
    return list(
        col(C.FINDING_RECORDS).find({"repo_full_name": repo, "is_active": True})
    )


# ── Finding record events / risk acceptances ────────────────────────────────
def insert_finding_event(
    *,
    finding_record_id: Any,
    event_type: str,
    actor: str,
    details: dict,
) -> None:
    col(C.FINDING_RECORD_EVENTS).insert_one(
        {
            "finding_record_id": str(finding_record_id),
            "event_type": event_type,
            "actor": actor,
            "details": details or {},
            "created_at": datetime.now(timezone.utc),
        }
    )


def insert_risk_acceptance(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    doc.setdefault("active", True)
    res = col(C.RISK_ACCEPTANCES).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def count_active_risk_acceptances() -> int:
    return col(C.RISK_ACCEPTANCES).count_documents({"active": True})


# ── Integration events helpers (extra) ──────────────────────────────────────
def list_integration_events(
    *, topic: Optional[str] = None, undelivered_only: bool = False, limit: int = 200
) -> list[dict]:
    q: dict = {}
    if topic:
        q["topic"] = topic
    if undelivered_only:
        q["delivered"] = False
    return list(
        col(C.INTEGRATION_EVENTS).find(q).sort("created_at", DESCENDING).limit(limit)
    )


def get_integration_event(event_id: Any) -> Optional[dict]:
    oid = _oid(event_id)
    if oid is not None:
        doc = col(C.INTEGRATION_EVENTS).find_one({"_id": oid})
        if doc:
            return doc
    return None


def update_integration_event(event_id: Any, fields: dict) -> bool:
    oid = _oid(event_id)
    if oid is None:
        return False
    return (
        col(C.INTEGRATION_EVENTS)
        .update_one({"_id": oid}, {"$set": fields})
        .matched_count
        > 0
    )


def finding_record_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "signature": doc.get("signature"),
        "scan_id": str(doc.get("scan_id")) if doc.get("scan_id") else None,
        "repo_full_name": doc.get("repo_full_name"),
        "pr_number": doc.get("pr_number"),
        "finding_type": doc.get("finding_type"),
        "finding_title": doc.get("finding_title"),
        "severity": doc.get("severity"),
        "status": doc.get("status"),
        "owner": doc.get("owner"),
        "team": doc.get("team"),
        "first_seen_at": (doc.get("first_seen_at") or datetime.now(timezone.utc)).isoformat(),
        "last_seen_at": (doc.get("last_seen_at") or datetime.now(timezone.utc)).isoformat(),
        "sla_due_at": doc.get("sla_due_at").isoformat() if doc.get("sla_due_at") else None,
        "is_active": bool(doc.get("is_active", True)),
        "metadata": doc.get("metadata", {}),
    }


# ── Organizations / API keys (embedded under organizations) ────────────────
def list_orgs() -> list[dict]:
    return list(col(C.ORGANIZATIONS).find().sort("created_at", DESCENDING))


def get_org_by_id(org_id: Any) -> Optional[dict]:
    oid = _oid(org_id)
    if oid is not None:
        return col(C.ORGANIZATIONS).find_one({"_id": oid})
    if _is_int_id(org_id):
        return col(C.ORGANIZATIONS).find_one({"legacy_id": int(org_id)})
    return None


def create_org(*, name: str, slug: str, plan: str = "free") -> dict:
    doc = {
        "name": name,
        "slug": slug.lower().strip(),
        "plan": plan,
        "settings": {},
        "members": [],
        "api_keys": [],
        "created_at": datetime.now(timezone.utc),
    }
    res = col(C.ORGANIZATIONS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def add_org_member(org_id: Any, *, user_id: str, role: str = "viewer") -> bool:
    oid = _oid(org_id)
    if oid is None:
        return False
    return (
        col(C.ORGANIZATIONS)
        .update_one(
            {"_id": oid},
            {
                "$addToSet": {
                    "members": {
                        "user_id": user_id,
                        "role": role,
                        "joined_at": datetime.now(timezone.utc),
                    }
                }
            },
        )
        .matched_count
        > 0
    )


def add_api_key(org_id: Any, *, name: str, key_hash: str, key_prefix: str, scopes: str) -> bool:
    oid = _oid(org_id)
    if oid is None:
        return False
    return (
        col(C.ORGANIZATIONS)
        .update_one(
            {"_id": oid},
            {
                "$push": {
                    "api_keys": {
                        "name": name,
                        "key_hash": key_hash,
                        "key_prefix": key_prefix,
                        "scopes": scopes,
                        "created_at": datetime.now(timezone.utc),
                        "revoked": False,
                    }
                }
            },
        )
        .matched_count
        > 0
    )


def find_org_by_api_key_hash(key_hash: str) -> Optional[dict]:
    return col(C.ORGANIZATIONS).find_one({"api_keys.key_hash": key_hash, "api_keys.revoked": False})


def org_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "name": doc.get("name"),
        "slug": doc.get("slug"),
        "plan": doc.get("plan", "free"),
        "settings": doc.get("settings", {}),
        "member_count": len(doc.get("members") or []),
        "api_key_count": len(doc.get("api_keys") or []),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
    }


# ── Policy versions ────────────────────────────────────────────────────────
def insert_policy_version(*, org_id: Any, repo: Optional[str], yaml_text: str, author_id: Optional[Any], change_summary: Optional[str] = None) -> dict:
    # Auto-increment version per (org, repo).
    cur_max = list(
        col(C.POLICY_VERSIONS)
        .find({"org_id": _oid(org_id), "repo_full_name": repo})
        .sort("version", DESCENDING)
        .limit(1)
    )
    next_v = (cur_max[0]["version"] + 1) if cur_max else 1
    doc = {
        "org_id": _oid(org_id),
        "repo_full_name": repo,
        "version": next_v,
        "yaml_text": yaml_text,
        "author_id": str(author_id) if author_id else None,
        "is_active": True,
        "change_summary": change_summary,
        "created_at": datetime.now(timezone.utc),
    }
    # Deactivate prior versions
    col(C.POLICY_VERSIONS).update_many(
        {"org_id": _oid(org_id), "repo_full_name": repo, "is_active": True},
        {"$set": {"is_active": False}},
    )
    res = col(C.POLICY_VERSIONS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def list_policy_versions(*, org_id: Any, repo: Optional[str] = None) -> list[dict]:
    q: dict = {"org_id": _oid(org_id)}
    if repo is not None:
        q["repo_full_name"] = repo
    return list(col(C.POLICY_VERSIONS).find(q).sort("version", DESCENDING))


def active_policy(*, org_id: Any, repo: Optional[str] = None) -> Optional[dict]:
    q = {"org_id": _oid(org_id), "is_active": True}
    if repo is not None:
        q["repo_full_name"] = repo
    return col(C.POLICY_VERSIONS).find_one(q, sort=[("version", DESCENDING)])


def policy_to_view(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "org_id": str(doc.get("org_id")) if doc.get("org_id") else None,
        "repo_full_name": doc.get("repo_full_name"),
        "version": int(doc.get("version", 1)),
        "is_active": bool(doc.get("is_active", True)),
        "yaml_text": doc.get("yaml_text", ""),
        "change_summary": doc.get("change_summary"),
        "created_at": (doc.get("created_at") or datetime.now(timezone.utc)).isoformat(),
    }


# ── Scan jobs ──────────────────────────────────────────────────────────────
def insert_scan_job(doc: dict) -> dict:
    doc.setdefault("created_at", datetime.now(timezone.utc))
    doc.setdefault("status", "pending")
    res = col(C.SCAN_JOBS).insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def get_scan_job(job_id: Any) -> Optional[dict]:
    oid = _oid(job_id)
    if oid is not None:
        doc = col(C.SCAN_JOBS).find_one({"_id": oid})
        if doc:
            return doc
    return col(C.SCAN_JOBS).find_one({"id": str(job_id)})


def update_scan_job(job_id: Any, fields: dict) -> bool:
    oid = _oid(job_id)
    q: dict
    if oid is not None:
        q = {"_id": oid}
    else:
        q = {"id": str(job_id)}
    return col(C.SCAN_JOBS).update_one(q, {"$set": fields}).matched_count > 0
