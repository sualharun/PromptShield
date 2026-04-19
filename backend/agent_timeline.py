"""Agent attack-surface time-series snapshots.

Every scan writes one row into the `agent_surface_timeline` collection
summarizing how big / how risky the agentic attack surface looked at that
moment. In Atlas this is a **time-series collection** with hours-granularity
buckets; on mongomock it's a regular collection.

The frontend's "attack surface over time" chart consumes this via
`GET /api/v2/agent-surface-timeline`. The aggregation does a 7-day rolling
average via `$setWindowFields` on Atlas (matches the existing
`risk_snapshots` pipeline) and falls back to a flat sort on mongomock.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from mongo import C, col

logger = logging.getLogger("promptshield.agent_timeline")


# Agentic finding-type sets (kept in sync with agent_alerts.py / agent_registry.py).
_TOOL_TYPES = {
    "DANGEROUS_TOOL_CAPABILITY",
    "TOOL_UNVALIDATED_ARGS",
    "TOOL_EXCESSIVE_SCOPE",
    "DANGEROUS_TOOL_BODY",
    "TOOL_PARAM_TO_EXEC",
    "TOOL_PARAM_TO_SHELL",
    "TOOL_PARAM_TO_SQL",
    "TOOL_UNRESTRICTED_FILE",
}
_OUTPUT_TYPES = {
    "LLM_OUTPUT_TO_EXEC",
    "LLM_OUTPUT_TO_SHELL",
    "LLM_OUTPUT_TO_SQL",
    "LLM_OUTPUT_UNESCAPED",
    "LLM_OUTPUT_EXEC",
    "LLM_OUTPUT_SHELL",
    "LLM_OUTPUT_SQL",
}
_RAG_TYPES = {"RAG_UNSANITIZED_CONTEXT"}

_SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _agent_risk_score(findings: Iterable[dict]) -> int:
    """Bounded 0-100 score derived only from agentic findings.
    Designed to be stable across scans of the same code, monotonic in
    severity. Matches the spirit of `compute_breakdown`'s per-category
    scoring without coupling to it."""
    score = 0
    for f in findings or []:
        ftype = f.get("type")
        if ftype not in _TOOL_TYPES and ftype not in _OUTPUT_TYPES and ftype not in _RAG_TYPES:
            continue
        score += _SEVERITY_WEIGHT.get((f.get("severity") or "low").lower(), 3)
    return min(100, score)


def snapshot_scan(
    findings: list[dict],
    *,
    scan_id: str,
    repo_full_name: Optional[str] = None,
    source: str = "web",
) -> Optional[dict]:
    """Write one time-series row for this scan.

    No-op when no agentic findings exist (avoids polluting the chart with
    flat zeros for unrelated scans). Distinct tool count is approximated
    from finding evidence — exact tool dedup happens in agent_registry.
    """
    findings = findings or []
    tool_findings = [f for f in findings if f.get("type") in _TOOL_TYPES]
    output_findings = [f for f in findings if f.get("type") in _OUTPUT_TYPES]
    rag_findings = [f for f in findings if f.get("type") in _RAG_TYPES]
    if not tool_findings and not output_findings and not rag_findings:
        return None

    critical_tool_count = sum(
        1 for f in tool_findings if (f.get("severity") or "").lower() == "critical"
    )

    # Tool-name approximation: line numbers are a reasonable proxy for
    # distinct tools in a single file. The authoritative count comes from
    # `agent_tools` aggregations.
    distinct_lines = {f.get("line_number") for f in tool_findings if f.get("line_number")}

    doc = {
        "ts": datetime.now(timezone.utc),
        "tool_count": len(distinct_lines) or len(tool_findings),
        "critical_tool_count": critical_tool_count,
        "unsafe_output_count": len(output_findings),
        "rag_unsanitized_count": len(rag_findings),
        "agent_risk_score": _agent_risk_score(findings),
        "meta": {
            "source": source,
            "repo_full_name": repo_full_name,
            "scan_id": scan_id,
        },
    }
    try:
        col(C.AGENT_SURFACE_TIMELINE).insert_one(doc)
    except Exception:
        logger.exception("agent_surface_timeline insert failed (non-fatal)")
        return None
    return doc


# ── Read API (powering /api/v2/agent-surface-timeline) ─────────────────────
def timeline_window(
    *,
    repo_full_name: Optional[str] = None,
    days: int = 30,
) -> dict:
    """Return chart-ready snapshot points + a trend delta.

    Tries Atlas `$setWindowFields` for an in-DB 7-day rolling average; falls
    back to a flat sort + Python smoothing on mongomock (which doesn't
    implement that stage).
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    match: dict[str, Any] = {"ts": {"$gte": since}}
    if repo_full_name:
        match["meta.repo_full_name"] = repo_full_name

    pipeline: list[dict] = [
        {"$match": match},
        {"$sort": {"ts": 1}},
        {
            "$setWindowFields": {
                "partitionBy": "$meta.repo_full_name",
                "sortBy": {"ts": 1},
                "output": {
                    "rolling_7d_risk": {
                        "$avg": "$agent_risk_score",
                        "window": {"range": [-7, 0], "unit": "day"},
                    },
                    "rolling_7d_tools": {
                        "$avg": "$tool_count",
                        "window": {"range": [-7, 0], "unit": "day"},
                    },
                },
            }
        },
    ]

    try:
        rows = list(col(C.AGENT_SURFACE_TIMELINE).aggregate(pipeline))
    except Exception as e:
        logger.info(
            "agent_timeline window-fn unavailable (%s) — falling back to flat sort", e
        )
        rows = list(
            col(C.AGENT_SURFACE_TIMELINE)
            .find(match)
            .sort("ts", 1)
        )
        # Python-side rolling average so the API contract is identical.
        _attach_rolling_avg(rows, days=7)

    points = []
    for r in rows:
        ts = r.get("ts")
        meta = r.get("meta") or {}
        points.append(
            {
                "ts": (ts or datetime.now(timezone.utc)).isoformat(),
                "tool_count": int(r.get("tool_count") or 0),
                "critical_tool_count": int(r.get("critical_tool_count") or 0),
                "unsafe_output_count": int(r.get("unsafe_output_count") or 0),
                "rag_unsanitized_count": int(r.get("rag_unsanitized_count") or 0),
                "agent_risk_score": int(r.get("agent_risk_score") or 0),
                "rolling_7d_risk": round(
                    float(r.get("rolling_7d_risk") or r.get("agent_risk_score") or 0), 2
                ),
                "rolling_7d_tools": round(
                    float(r.get("rolling_7d_tools") or r.get("tool_count") or 0), 2
                ),
                "repo_full_name": meta.get("repo_full_name"),
                "source": meta.get("source"),
            }
        )

    risk_delta = 0
    surface_delta = 0
    if len(points) >= 2:
        risk_delta = round(points[-1]["agent_risk_score"] - points[0]["agent_risk_score"], 2)
        surface_delta = round(points[-1]["tool_count"] - points[0]["tool_count"], 2)

    return {
        "points": points,
        "trend": {
            "risk_delta": risk_delta,
            "surface_delta": surface_delta,
            "window_days": days,
        },
    }


def _attach_rolling_avg(rows: list[dict], *, days: int) -> None:
    """In-place 7-day rolling average for mongomock fallback."""
    if not rows:
        return
    window = timedelta(days=days)
    for i, row in enumerate(rows):
        ts = row.get("ts")
        if not ts:
            continue
        cutoff = ts - window
        bucket = [r for r in rows[: i + 1] if r.get("ts") and r["ts"] >= cutoff]
        if not bucket:
            continue
        row["rolling_7d_risk"] = sum(
            int(r.get("agent_risk_score") or 0) for r in bucket
        ) / len(bucket)
        row["rolling_7d_tools"] = sum(
            int(r.get("tool_count") or 0) for r in bucket
        ) / len(bucket)
