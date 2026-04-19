"""One-shot migration: copy every row from a legacy SQLite file into Mongo.

Uses the stdlib `sqlite3` module only.

Run once after pointing MONGODB_URI at your Atlas cluster:

    python backend/scripts/migrate_sqlite_to_mongo.py

Set DATABASE_URL to your SQLite file, e.g. `sqlite:///./promptshield.db`
(see `config.Settings.DATABASE_URL`).

What it does:
  • Reads every row from each legacy table that exists in the file.
  • Reshapes rows into idiomatic Mongo documents (JSON columns parsed, GitHub
    fields grouped under `github`, `llm_targets` CSV → array, etc.)
  • Writes `legacy_id` where applicable so `/api/scans/42` still resolves via
    the repository int-id fallback.
  • Idempotent: matching `legacy_id` (or natural keys for jobs) is upserted.

Safe to re-run. Does NOT delete the SQLite file.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Allow running from repo root
HERE = Path(__file__).resolve()
BACKEND = HERE.parent.parent
sys.path.insert(0, str(BACKEND))

from config import settings  # noqa: E402
from mongo import C, col, init_collections  # noqa: E402


# ── SQLite URL → filesystem path ────────────────────────────────────────────
def _sqlite_file_path(database_url: str) -> Path:
    u = database_url.strip()
    if not u.startswith("sqlite:///"):
        raise ValueError(
            f"DATABASE_URL must be a sqlite:/// URL (got {u[:48]}…). "
            "Example: sqlite:///./promptshield.db"
        )
    rest = u[len("sqlite:///") :]
    if rest == ":memory:":
        raise ValueError("Cannot migrate from an in-memory SQLite database.")
    p = Path(rest)
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


# ── Helpers ─────────────────────────────────────────────────────────────────
def _parse_json(s: str | None, default: Any) -> Any:
    if not s:
        return default
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default


def _csv(s: str | None) -> list[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]


def _utc(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(float(val), tz=timezone.utc)
    if isinstance(val, bytes):
        try:
            val = val.decode("utf-8")
        except Exception:
            return datetime.now(timezone.utc)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
        try:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Iterable[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    ).fetchone()
    return r is not None


def _rowdict(r: sqlite3.Row) -> dict[str, Any]:
    return {k: r[k] for k in r.keys()}


# ── Per-collection migrators ────────────────────────────────────────────────
def migrate_scans(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows(conn, "SELECT * FROM scans"):
        s = _rowdict(r)
        github = {
            "repo_full_name": s.get("repo_full_name"),
            "pr_number": s.get("pr_number"),
            "commit_sha": s.get("commit_sha"),
            "pr_title": s.get("pr_title"),
            "pr_url": s.get("pr_url"),
            "author_login": s.get("author_login"),
        }
        github = github if any(v is not None for v in github.values()) else None
        doc = {
            "legacy_id": s["id"],
            "created_at": _utc(s.get("created_at")) or datetime.now(timezone.utc),
            "input_text": s.get("input_text") or "",
            "risk_score": float(s.get("risk_score") or 0),
            "findings": _parse_json(s.get("findings_json"), []),
            "counts": {
                "static": int(s.get("static_count") or 0),
                "ai": int(s.get("ai_count") or 0),
                "total": int(s.get("total_count") or 0),
            },
            "source": s.get("source") or "web",
            "llm_targets": _csv(s.get("llm_targets")),
            "org_id": str(s["org_id"]) if s.get("org_id") is not None else None,
            "github": github,
            "score_breakdown": _parse_json(s.get("score_breakdown_json"), None),
            "graph_analysis": _parse_json(s.get("graph_analysis_json"), None),
        }
        col(C.SCANS).update_one({"legacy_id": s["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_audit_logs(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows(conn, "SELECT * FROM audit_logs"):
        a = _rowdict(r)
        sid = a.get("scan_id")
        doc = {
            "legacy_id": a["id"],
            "created_at": _utc(a.get("created_at")) or datetime.now(timezone.utc),
            "actor": a.get("actor") or "system",
            "action": a["action"],
            "source": a.get("source") or "web",
            "repo_full_name": a.get("repo_full_name"),
            "pr_number": a.get("pr_number"),
            "scan_id": str(sid) if sid is not None else None,
            "details": _parse_json(a.get("details_json"), {}),
            "client_ip": a.get("client_ip"),
        }
        col(C.AUDIT_LOGS).update_one({"legacy_id": a["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_risk_snapshots(conn: sqlite3.Connection) -> int:
    n = 0
    coll = col(C.RISK_SNAPSHOTS)
    is_timeseries = False
    try:
        info = coll.options() if hasattr(coll, "options") else {}
        is_timeseries = "timeseries" in (info or {})
    except Exception:
        is_timeseries = False

    for r in _rows(conn, "SELECT * FROM risk_snapshots"):
        row = _rowdict(r)
        try:
            ts = datetime.strptime(row["snapshot_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)
        doc = {
            "ts": ts,
            "meta": {"source": row.get("source") or "github"},
            "risk_score": float(row.get("risk_score") or 0),
            "critical_count": int(row.get("critical_count") or 0),
            "high_count": int(row.get("high_count") or 0),
            "medium_count": int(row.get("medium_count") or 0),
            "low_count": int(row.get("low_count") or 0),
            "scan_count": int(row.get("scan_count") or 0),
        }
        if is_timeseries:
            coll.insert_one(doc)
        else:
            doc["legacy_id"] = row["id"]
            coll.update_one({"legacy_id": row["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_finding_records(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows(conn, "SELECT * FROM finding_records"):
        f = _rowdict(r)
        doc = {
            "legacy_id": f["id"],
            "signature": f["signature"],
            "scan_id": f.get("scan_id"),
            "last_seen_scan_id": f.get("last_seen_scan_id"),
            "repo_full_name": f.get("repo_full_name"),
            "pr_number": f.get("pr_number"),
            "finding_type": f.get("finding_type"),
            "finding_title": f.get("finding_title"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "owner": f.get("owner"),
            "team": f.get("team"),
            "first_seen_at": _utc(f.get("first_seen_at")),
            "last_seen_at": _utc(f.get("last_seen_at")),
            "triaged_at": _utc(f.get("triaged_at")),
            "in_progress_at": _utc(f.get("in_progress_at")),
            "fixed_at": _utc(f.get("fixed_at")),
            "verified_at": _utc(f.get("verified_at")),
            "suppressed_at": _utc(f.get("suppressed_at")),
            "closed_at": _utc(f.get("closed_at")),
            "sla_due_at": _utc(f.get("sla_due_at")),
            "is_active": bool(f.get("is_active")),
            "metadata": _parse_json(f.get("metadata_json"), {}),
        }
        col(C.FINDING_RECORDS).update_one({"legacy_id": f["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_suppressions(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows(conn, "SELECT * FROM finding_suppressions"):
        s = _rowdict(r)
        doc = {
            "legacy_id": s["id"],
            "signature": s["signature"],
            "finding_type": s.get("finding_type"),
            "finding_title": s.get("finding_title"),
            "repo_full_name": s.get("repo_full_name"),
            "reason": s.get("reason"),
            "suppressed_by": s.get("suppressed_by"),
            "created_at": _utc(s.get("created_at")) or datetime.now(timezone.utc),
        }
        col(C.FINDING_SUPPRESSIONS).update_one({"legacy_id": s["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_users(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows(conn, "SELECT * FROM users"):
        u = _rowdict(r)
        doc = {
            "legacy_id": u["id"],
            "email": (u.get("email") or "").lower().strip(),
            "name": u.get("name"),
            "password_hash": u.get("password_hash"),
            "role": u.get("role") or "viewer",
            "created_at": _utc(u.get("created_at")) or datetime.now(timezone.utc),
        }
        col(C.USERS).update_one({"legacy_id": u["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_orgs_with_embedded(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "organizations"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM organizations"):
        org = _rowdict(r)
        oid = org["id"]
        members = [
            {
                "user_id": str(m["user_id"]),
                "role": m.get("role"),
                "created_at": _utc(m.get("created_at")) or datetime.now(timezone.utc),
            }
            for m in (_rowdict(x) for x in _rows(conn, "SELECT * FROM org_members WHERE org_id=?", (oid,)))
        ]
        api_keys = [
            {
                "name": k.get("name"),
                "key_hash": k.get("key_hash"),
                "key_prefix": k.get("key_prefix"),
                "scopes": k.get("scopes"),
                "created_by": str(k.get("created_by")),
                "created_at": _utc(k.get("created_at")) or datetime.now(timezone.utc),
                "last_used_at": _utc(k.get("last_used_at")),
                "revoked": bool(k.get("revoked")),
            }
            for k in (_rowdict(x) for x in _rows(conn, "SELECT * FROM api_keys WHERE org_id=?", (oid,)))
        ]
        doc = {
            "legacy_id": oid,
            "name": org.get("name"),
            "slug": org.get("slug"),
            "plan": org.get("plan"),
            "settings": _parse_json(org.get("settings_json"), {}),
            "members": members,
            "api_keys": api_keys,
            "created_at": _utc(org.get("created_at")) or datetime.now(timezone.utc),
        }
        col(C.ORGANIZATIONS).update_one({"legacy_id": oid}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_misc(conn: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}

    if _table_exists(conn, "dependencies"):
        for r in _rows(conn, "SELECT * FROM dependencies"):
            row = _rowdict(r)
            col(C.DEPENDENCIES).update_one(
                {"legacy_id": row["id"]},
                {
                    "$set": {
                        "legacy_id": row["id"],
                        "name": row.get("name"),
                        "version": row.get("version"),
                        "registry": row.get("registry"),
                        "ecosystem": row.get("ecosystem"),
                        "risk_score": float(row.get("risk_score") or 0),
                        "cve_count": int(row.get("cve_count") or 0),
                        "created_at": _utc(row.get("created_at")) or datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            counts["dependencies"] = counts.get("dependencies", 0) + 1

    if _table_exists(conn, "integration_events"):
        for r in _rows(conn, "SELECT * FROM integration_events"):
            e = _rowdict(r)
            col(C.INTEGRATION_EVENTS).update_one(
                {"legacy_id": e["id"]},
                {
                    "$set": {
                        "legacy_id": e["id"],
                        "topic": e.get("topic"),
                        "payload": _parse_json(e.get("payload_json"), {}),
                        "delivered": bool(e.get("delivered")),
                        "delivery_target": e.get("delivery_target"),
                        "attempts": int(e.get("attempts") or 0),
                        "created_at": _utc(e.get("created_at")) or datetime.now(timezone.utc),
                        "delivered_at": _utc(e.get("delivered_at")),
                    }
                },
                upsert=True,
            )
            counts["integration_events"] = counts.get("integration_events", 0) + 1

    if _table_exists(conn, "graph_nodes"):
        for r in _rows(conn, "SELECT * FROM graph_nodes"):
            n = _rowdict(r)
            col(C.GRAPH_NODES).update_one(
                {"legacy_id": n["id"]},
                {
                    "$set": {
                        "legacy_id": n["id"],
                        "scan_id": n.get("scan_id"),
                        "node_id": n.get("node_id"),
                        "node_type": n.get("node_type"),
                        "name": n.get("name"),
                        "risk_score": float(n.get("risk_score") or 0),
                        "props": _parse_json(n.get("props_json"), {}),
                        "created_at": _utc(n.get("created_at")) or datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            counts["graph_nodes"] = counts.get("graph_nodes", 0) + 1

    if _table_exists(conn, "graph_edges"):
        for r in _rows(conn, "SELECT * FROM graph_edges"):
            e = _rowdict(r)
            col(C.GRAPH_EDGES).update_one(
                {"legacy_id": e["id"]},
                {
                    "$set": {
                        "legacy_id": e["id"],
                        "scan_id": e.get("scan_id"),
                        "source_node_id": e.get("source_node_id"),
                        "target_node_id": e.get("target_node_id"),
                        "edge_type": e.get("edge_type"),
                        "risk": e.get("risk"),
                        "props": _parse_json(e.get("props_json"), {}),
                        "created_at": _utc(e.get("created_at")) or datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            counts["graph_edges"] = counts.get("graph_edges", 0) + 1

    return counts


def migrate_policy_versions(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "policy_versions"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM policy_versions"):
        p = _rowdict(r)
        doc = {
            "legacy_id": p["id"],
            "org_id": str(p["org_id"]) if p.get("org_id") is not None else None,
            "repo_full_name": p.get("repo_full_name"),
            "version": int(p.get("version") or 1),
            "yaml_text": p.get("yaml_text") or "",
            "author_id": str(p["author_id"]) if p.get("author_id") is not None else None,
            "created_at": _utc(p.get("created_at")) or datetime.now(timezone.utc),
            "is_active": bool(p.get("is_active")),
            "change_summary": p.get("change_summary"),
        }
        col(C.POLICY_VERSIONS).update_one({"legacy_id": p["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_scan_jobs(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "scan_jobs"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM scan_jobs"):
        j = _rowdict(r)
        rsid = j.get("result_scan_id")
        doc = {
            "id": j.get("id"),
            "org_id": str(j["org_id"]) if j.get("org_id") is not None else None,
            "status": j.get("status") or "pending",
            "job_type": j.get("job_type") or "scan",
            "input_text": j.get("input_text") or "",
            "result_scan_id": str(rsid) if rsid is not None else None,
            "error_message": j.get("error_message"),
            "retry_count": int(j.get("retry_count") or 0),
            "max_retries": int(j.get("max_retries") or 3),
            "created_at": _utc(j.get("created_at")) or datetime.now(timezone.utc),
            "started_at": _utc(j.get("started_at")),
            "completed_at": _utc(j.get("completed_at")),
            "created_by": str(j["created_by"]) if j.get("created_by") is not None else None,
        }
        col(C.SCAN_JOBS).update_one({"id": j.get("id")}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_eval_runs(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "eval_runs"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM eval_runs"):
        e = _rowdict(r)
        doc = {
            "legacy_id": e["id"],
            "run_at": _utc(e.get("run_at")) or datetime.now(timezone.utc),
            "scanner_version": e.get("scanner_version") or "0.3.0",
            "total_samples": int(e.get("total_samples") or 0),
            "true_positives": int(e.get("true_positives") or 0),
            "true_negatives": int(e.get("true_negatives") or 0),
            "false_positives": int(e.get("false_positives") or 0),
            "false_negatives": int(e.get("false_negatives") or 0),
            "precision": float(e.get("precision") or 0),
            "recall": float(e.get("recall") or 0),
            "f1": float(e.get("f1") or 0),
            "accuracy": float(e.get("accuracy") or 0),
            "details": _parse_json(e.get("details_json"), []),
            "regression_from_previous": bool(e.get("regression_from_previous")),
        }
        col(C.EVAL_RUNS).update_one({"legacy_id": e["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_baseline_findings(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "baseline_findings"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM baseline_findings"):
        b = _rowdict(r)
        doc = {
            "legacy_id": b["id"],
            "repo_full_name": b.get("repo_full_name"),
            "org_id": str(b["org_id"]) if b.get("org_id") is not None else None,
            "signature": b.get("signature"),
            "finding_type": b.get("finding_type"),
            "severity": b.get("severity"),
            "first_seen_at": _utc(b.get("first_seen_at")) or datetime.now(timezone.utc),
            "last_seen_at": _utc(b.get("last_seen_at")) or datetime.now(timezone.utc),
            "acknowledged": bool(b.get("acknowledged")),
            "acknowledged_by": b.get("acknowledged_by"),
        }
        col(C.BASELINE_FINDINGS).update_one({"legacy_id": b["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_finding_record_events(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "finding_record_events"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM finding_record_events"):
        e = _rowdict(r)
        doc = {
            "legacy_id": e["id"],
            "finding_record_id": str(e.get("finding_record_id")),
            "event_type": e.get("event_type"),
            "actor": e.get("actor") or "system",
            "details": _parse_json(e.get("details_json"), {}),
            "created_at": _utc(e.get("created_at")) or datetime.now(timezone.utc),
        }
        col(C.FINDING_RECORD_EVENTS).update_one({"legacy_id": e["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def migrate_risk_acceptances(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "risk_acceptances"):
        return 0
    n = 0
    for r in _rows(conn, "SELECT * FROM risk_acceptances"):
        a = _rowdict(r)
        doc = {
            "legacy_id": a["id"],
            "finding_record_id": a.get("finding_record_id"),
            "reason": a.get("reason") or "",
            "approved_by": a.get("approved_by") or "security",
            "expires_at": _utc(a.get("expires_at")),
            "active": bool(a.get("active", True)),
            "created_at": _utc(a.get("created_at")) or datetime.now(timezone.utc),
        }
        col(C.RISK_ACCEPTANCES).update_one({"legacy_id": a["id"]}, {"$set": doc}, upsert=True)
        n += 1
    return n


def main() -> int:
    if not settings.MONGODB_URI:
        print("ERROR: MONGODB_URI not set — nothing to migrate to.")
        return 2

    db_path = _sqlite_file_path(settings.DATABASE_URL)
    if not db_path.is_file():
        print(f"ERROR: SQLite file not found: {db_path}")
        return 2

    init_collections()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        print("Migrating SQLite -> MongoDB Atlas")
        print(f"  Source: {db_path}")
        host = settings.MONGODB_URI.split("@")[-1].split("/")[0]
        print(f"  Target: {settings.MONGODB_DB} on {host}")
        results: dict[str, int] = {}
        for name, fn in [
            ("scans", lambda: migrate_scans(conn)),
            ("audit_logs", lambda: migrate_audit_logs(conn)),
            ("risk_snapshots", lambda: migrate_risk_snapshots(conn)),
            ("finding_records", lambda: migrate_finding_records(conn)),
            ("finding_suppressions", lambda: migrate_suppressions(conn)),
            ("users", lambda: migrate_users(conn)),
            ("organizations", lambda: migrate_orgs_with_embedded(conn)),
        ]:
            if _table_exists(conn, name):
                try:
                    results[name] = fn()
                except sqlite3.OperationalError as e:
                    print(f"  skip {name}: {e}")
                    results[name] = 0
            else:
                results[name] = 0

        results.update(migrate_misc(conn))
        if _table_exists(conn, "policy_versions"):
            results["policy_versions"] = migrate_policy_versions(conn)
        if _table_exists(conn, "scan_jobs"):
            results["scan_jobs"] = migrate_scan_jobs(conn)
        if _table_exists(conn, "eval_runs"):
            results["eval_runs"] = migrate_eval_runs(conn)
        if _table_exists(conn, "baseline_findings"):
            results["baseline_findings"] = migrate_baseline_findings(conn)
        if _table_exists(conn, "finding_record_events"):
            results["finding_record_events"] = migrate_finding_record_events(conn)
        if _table_exists(conn, "risk_acceptances"):
            results["risk_acceptances"] = migrate_risk_acceptances(conn)

        print("\nMigration complete:")
        for name, count in sorted(results.items()):
            print(f"   {name:<24} {count:>6} docs")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
