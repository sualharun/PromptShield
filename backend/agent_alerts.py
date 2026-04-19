"""Critical-finding alert fan-out for agentic security findings.

When a scan produces a critical agentic finding (DANGEROUS_TOOL_*, LLM_OUTPUT_*
or RAG_UNSANITIZED_CONTEXT at severity=critical|high), we cross-post a row
into the `agent_alerts` collection so:

  • An Atlas Trigger (`alert_on_critical_agent_finding.js`) can fan it out to
    Slack / PagerDuty / SIEM server-side — a clean Mongo-native alerting
    story for the demo.
  • Even WITHOUT the trigger configured, the alert collection still gets
    populated by Python so the dashboard always has data ("degraded mode").
  • A consumer can ack alerts via /api/v2/agent-alerts/{id}/acknowledge.

This is *defense in depth*: the same alert can be written by both Python and
the trigger; we dedupe by signature so the user sees one row.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from bson import ObjectId
from pymongo import DESCENDING

from mongo import C, col, using_mock

logger = logging.getLogger("promptshield.agent_alerts")


# Severity threshold for raising an alert. We want signal, not noise — so
# only critical & high agentic findings escalate.
_ALERT_SEVERITIES = {"critical", "high"}

# Finding types that count as "agentic" for alert purposes.
_AGENTIC_TYPES = {
    # Tool-side findings
    "DANGEROUS_TOOL_CAPABILITY",
    "TOOL_UNVALIDATED_ARGS",
    "TOOL_EXCESSIVE_SCOPE",
    "DANGEROUS_TOOL_BODY",
    "TOOL_PARAM_TO_EXEC",
    "TOOL_PARAM_TO_SHELL",
    "TOOL_PARAM_TO_SQL",
    "TOOL_UNRESTRICTED_FILE",
    # Output-side findings
    "LLM_OUTPUT_TO_EXEC",
    "LLM_OUTPUT_TO_SHELL",
    "LLM_OUTPUT_TO_SQL",
    "LLM_OUTPUT_UNESCAPED",
    "LLM_OUTPUT_EXEC",
    "LLM_OUTPUT_SHELL",
    "LLM_OUTPUT_SQL",
    # Indirect-injection
    "RAG_UNSANITIZED_CONTEXT",
    # Aliases produced by agent_security_scan.py — same severity rules
    # apply (only critical/high get escalated to an alert).
    "AGENT_FUNCTION_EXPOSURE",
    "DANGEROUS_SINK",
    "UNVALIDATED_FUNCTION_PARAM_TO_SINK",
}


def _signature(finding: dict, *, repo: Optional[str], scan_id: str) -> str:
    """Stable key per (repo, type, line) — repeats of the same alert dedupe.
    Includes scan_id only as a tiebreaker for ad-hoc web scans where there's
    no repo to anchor against."""
    parts = [
        finding.get("type") or "UNKNOWN",
        str(finding.get("line_number") or ""),
        repo or f"scan:{scan_id}",
        (finding.get("evidence") or "")[:80],
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def fan_out_critical_alerts(
    findings: Iterable[dict],
    *,
    scan_id: str,
    repo_full_name: Optional[str] = None,
    pr_number: Optional[int] = None,
    source: str = "web",
) -> list[dict]:
    """Persist one `agent_alerts` row per critical agentic finding.

    Idempotent on signature — re-running the same scan won't duplicate rows.
    Returns the list of newly-inserted alert docs (existing alerts return as
    `None` and are filtered out).
    """
    inserted: list[dict] = []
    now = datetime.now(timezone.utc)
    for f in findings or []:
        ftype = f.get("type")
        sev = (f.get("severity") or "").lower()
        if ftype not in _AGENTIC_TYPES or sev not in _ALERT_SEVERITIES:
            continue
        sig = _signature(f, repo=repo_full_name, scan_id=scan_id)
        doc = {
            "signature": sig,
            "created_at": now,
            "scan_id": scan_id,
            "source": source,
            "repo_full_name": repo_full_name,
            "pr_number": pr_number,
            "finding_type": ftype,
            "severity": sev,
            "title": f.get("title") or ftype,
            "description": f.get("description"),
            "evidence": (f.get("evidence") or "")[:300],
            "line_number": f.get("line_number"),
            "cwe": f.get("cwe"),
            "owasp": f.get("owasp"),
            "remediation": f.get("remediation"),
            "acknowledged": False,
            "channels_notified": [],  # Atlas Trigger fills this in if configured
            "_written_by": "python_pipeline",
        }
        try:
            res = col(C.AGENT_ALERTS).update_one(
                {"signature": sig},
                {
                    "$setOnInsert": doc,
                    "$inc": {"occurrences": 1},
                    "$set": {"last_seen_at": now},
                },
                upsert=True,
            )
            if res.upserted_id is not None:
                doc["_id"] = res.upserted_id
                inserted.append(doc)
        except Exception:
            logger.exception("agent_alerts upsert failed (signature=%s)", sig)

    if inserted:
        logger.info(
            "agent_alerts: %d new critical alert(s) (repo=%s, scan_id=%s)",
            len(inserted),
            repo_full_name or "<web>",
            scan_id,
        )
    return inserted


# ── Read API ───────────────────────────────────────────────────────────────
def list_alerts(
    *,
    repo_full_name: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 50,
) -> list[dict]:
    q: dict[str, Any] = {}
    if repo_full_name:
        q["repo_full_name"] = repo_full_name
    if acknowledged is not None:
        q["acknowledged"] = acknowledged
    return list(
        col(C.AGENT_ALERTS).find(q).sort("created_at", DESCENDING).limit(limit)
    )


def alert_to_view(doc: dict) -> dict:
    if not doc:
        return {}
    return {
        "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "signature": doc.get("signature"),
        "scan_id": doc.get("scan_id"),
        "source": doc.get("source"),
        "repo_full_name": doc.get("repo_full_name"),
        "pr_number": doc.get("pr_number"),
        "finding_type": doc.get("finding_type"),
        "severity": doc.get("severity"),
        "title": doc.get("title"),
        "description": doc.get("description"),
        "evidence": doc.get("evidence"),
        "line_number": doc.get("line_number"),
        "cwe": doc.get("cwe"),
        "owasp": doc.get("owasp"),
        "remediation": doc.get("remediation"),
        "acknowledged": bool(doc.get("acknowledged")),
        "acknowledged_by": doc.get("acknowledged_by"),
        "channels_notified": doc.get("channels_notified") or [],
        "occurrences": int(doc.get("occurrences") or 1),
        "created_at": (
            doc.get("created_at") or datetime.now(timezone.utc)
        ).isoformat(),
        "last_seen_at": (
            doc.get("last_seen_at") or doc.get("created_at") or datetime.now(timezone.utc)
        ).isoformat(),
        "written_by": doc.get("_written_by") or "python_pipeline",
    }


def acknowledge(alert_id: str, *, by: str) -> bool:
    try:
        oid = ObjectId(alert_id)
    except Exception:
        return False
    res = col(C.AGENT_ALERTS).update_one(
        {"_id": oid},
        {
            "$set": {
                "acknowledged": True,
                "acknowledged_by": by,
                "acknowledged_at": datetime.now(timezone.utc),
            }
        },
    )
    return res.matched_count > 0


def trigger_status() -> dict:
    """Quick liveness — 'is the trigger likely deployed?' = whether any alert
    in the last 24h was written by the trigger rather than by Python."""
    since = datetime.now(timezone.utc).replace(microsecond=0)
    # Look back a day. Fine to scan the small alerts collection directly.
    lookback = since.replace(hour=0)
    cnt_trigger = col(C.AGENT_ALERTS).count_documents(
        {"_written_by": "atlas_trigger", "created_at": {"$gte": lookback}}
    )
    cnt_python = col(C.AGENT_ALERTS).count_documents(
        {"_written_by": "python_pipeline", "created_at": {"$gte": lookback}}
    )
    return {
        "atlas_trigger_active": cnt_trigger > 0,
        "alerts_from_trigger_24h": cnt_trigger,
        "alerts_from_python_24h": cnt_python,
        "mongomock_mode": using_mock(),
        "note": (
            "Atlas Trigger is optional — when not deployed, Python writes "
            "the same alerts so the dashboard always has data."
        ),
    }
