"""Atlas Search ($search) — Lucene-grade FTS across the scans collection.

Index name: `scans_text_idx` (defined in scripts/atlas_indexes/).

Features exposed:
  • search(q)       — fuzzy, multi-field text search across scans + findings
  • autocomplete(q) — type-ahead for the dashboard search bar
  • facet_counts(q) — per-severity / per-CWE counts in the same response

All three gracefully fall back to a regex-based scan over the collection when
running on mongomock or before the Atlas Search index is provisioned. The
fallback is slower but keeps the API contract stable so the frontend works
end-to-end during development.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from pymongo.errors import OperationFailure

from mongo import C, col, using_mock

logger = logging.getLogger("promptshield.atlas_search")

SEARCH_INDEX_NAME = "scans_text_idx"


# ── Atlas $search ───────────────────────────────────────────────────────────
def search(q: str, *, limit: int = 25, source: Optional[str] = None) -> list[dict]:
    if not q or not q.strip():
        return []
    if not using_mock():
        try:
            return _atlas_search(q, limit=limit, source=source)
        except OperationFailure as e:
            logger.warning("$search failed (%s) — falling back to regex", e)
        except Exception as e:
            logger.warning("$search error (%s) — falling back to regex", e)
    return _regex_fallback(q, limit=limit, source=source)


def _atlas_search(q: str, *, limit: int, source: Optional[str]) -> list[dict]:
    must: list[dict] = [
        {
            "compound": {
                "should": [
                    {
                        "text": {
                            "query": q,
                            "path": ["input_text", "findings.title", "findings.evidence", "github.pr_title", "github.repo_full_name"],
                            "fuzzy": {"maxEdits": 1},
                        }
                    },
                    {"autocomplete": {"query": q, "path": "findings.title"}},
                ],
                "minimumShouldMatch": 1,
            }
        }
    ]
    if source:
        must.append({"equals": {"path": "source", "value": source}})

    pipeline = [
        {
            "$search": {
                "index": SEARCH_INDEX_NAME,
                "compound": {"must": must},
                "highlight": {"path": ["input_text", "findings.title", "findings.evidence"]},
            }
        },
        {"$limit": limit},
        {
            "$project": {
                "input_text": 1,
                "risk_score": 1,
                "findings": 1,
                "source": 1,
                "github": 1,
                "created_at": 1,
                "score": {"$meta": "searchScore"},
                "highlights": {"$meta": "searchHighlights"},
            }
        },
    ]
    return list(col(C.SCANS).aggregate(pipeline))


def _regex_fallback(q: str, *, limit: int, source: Optional[str]) -> list[dict]:
    pat = re.compile(re.escape(q), re.IGNORECASE)
    base: dict = {
        "$or": [
            {"input_text": pat},
            {"findings.title": pat},
            {"findings.evidence": pat},
            {"github.pr_title": pat},
            {"github.repo_full_name": pat},
        ]
    }
    if source:
        base["source"] = source
    return list(col(C.SCANS).find(base).limit(limit))


# ── Autocomplete ────────────────────────────────────────────────────────────
def autocomplete(prefix: str, *, limit: int = 8) -> list[str]:
    if not prefix:
        return []
    if not using_mock():
        try:
            pipeline = [
                {
                    "$search": {
                        "index": SEARCH_INDEX_NAME,
                        "autocomplete": {"query": prefix, "path": "findings.title"},
                    }
                },
                {"$limit": limit},
                {"$unwind": "$findings"},
                {"$match": {"findings.title": {"$regex": prefix, "$options": "i"}}},
                {"$group": {"_id": "$findings.title"}},
                {"$limit": limit},
            ]
            return [d["_id"] for d in col(C.SCANS).aggregate(pipeline) if d.get("_id")]
        except Exception as e:
            logger.warning("autocomplete fell back: %s", e)
    # Fallback: scan distinct titles
    titles = set()
    pat = re.compile("^" + re.escape(prefix), re.IGNORECASE)
    for doc in col(C.SCANS).find({"findings.title": pat}, {"findings.title": 1}).limit(limit * 3):
        for f in doc.get("findings", []):
            t = f.get("title")
            if t and pat.search(t):
                titles.add(t)
            if len(titles) >= limit:
                break
        if len(titles) >= limit:
            break
    return sorted(titles)[:limit]


# ── Facet counts (severity, CWE) ────────────────────────────────────────────
def facet_counts(q: Optional[str] = None) -> dict:
    """Per-severity + per-CWE distribution for the search results.
    Uses Atlas $searchMeta when available; falls back to a plain $group."""
    if q and not using_mock():
        try:
            pipeline = [
                {
                    "$searchMeta": {
                        "index": SEARCH_INDEX_NAME,
                        "facet": {
                            "operator": {
                                "text": {
                                    "query": q,
                                    "path": ["input_text", "findings.title"],
                                }
                            },
                            "facets": {
                                "severityFacet": {
                                    "type": "string",
                                    "path": "findings.severity",
                                },
                                "cweFacet": {
                                    "type": "string",
                                    "path": "findings.cwe",
                                },
                            },
                        },
                    }
                }
            ]
            res = list(col(C.SCANS).aggregate(pipeline))
            if res:
                return res[0].get("facet", {})
        except Exception as e:
            logger.warning("facet_counts fell back: %s", e)

    # Plain fallback — group on every finding
    sev = list(
        col(C.SCANS).aggregate(
            [
                {"$unwind": "$findings"},
                {"$group": {"_id": "$findings.severity", "count": {"$sum": 1}}},
            ]
        )
    )
    cwe = list(
        col(C.SCANS).aggregate(
            [
                {"$unwind": "$findings"},
                {"$match": {"findings.cwe": {"$ne": None}}},
                {"$group": {"_id": "$findings.cwe", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
            ]
        )
    )
    return {
        "severityFacet": {"buckets": [{"_id": s["_id"], "count": s["count"]} for s in sev if s["_id"]]},
        "cweFacet": {"buckets": [{"_id": c["_id"], "count": c["count"]} for c in cwe]},
    }
