"""Hybrid search: combine $vectorSearch + $search via $rankFusion.

This is the "smart search bar" from the demo. A single pipeline that:
  1) runs Atlas Vector Search for semantic similarity
  2) runs Atlas Search ($search, Lucene) for keyword / fuzzy matches
  3) merges both with Reciprocal Rank Fusion ($rankFusion stage), which
     converts each list's positions into 1/(rank + 60) and sums the scores

The resulting list ranks documents that show up in *both* lists higher than
documents that appear in only one — exactly what you want for "find findings
about credential leaks" when the literal words "credential" or "leak" might
not appear in the matching document.

Falls back to a manual reciprocal-rank-fusion in Python when the cluster
doesn't expose `$rankFusion` (mongomock, free tier in some regions, etc.).
"""
from __future__ import annotations

import logging
from typing import Optional

from pymongo.errors import OperationFailure

from atlas_search import SEARCH_INDEX_NAME, _atlas_search, _regex_fallback
from embeddings import embed
from mongo import C, col, using_mock
from vector_search import _atlas_search as _vec_search, _local_search, cosine

# Scans carry their own embedding — default hybrid search stays on scans.
_SCANS_VECTOR_INDEX = "scans_vector_idx"

logger = logging.getLogger("promptshield.hybrid_search")


def hybrid_search(
    q: str,
    *,
    k: int = 20,
    vector_weight: float = 1.0,
    text_weight: float = 1.0,
    source: Optional[str] = None,
    collection: Optional[str] = None,
    vector_index: Optional[str] = None,
    text_index: Optional[str] = None,
    text_paths: Optional[list[str]] = None,
    embedding_text: Optional[str] = None,
) -> list[dict]:
    """Top-k documents matching `q` via fused semantic + lexical search.

    Default target is the SCANS collection (legacy behavior — every existing
    caller of this function gets scans search with no kwargs). Pass `collection`
    + `vector_index` + `text_index` + `text_paths` to run the same pipeline
    over a different collection (e.g. `agent_tools`).

    Args:
      q             — user query string.
      k             — top-k results to return.
      vector_weight — weight applied to the vectorSearch ranking in RRF.
      text_weight   — weight applied to the $search ranking in RRF.
      source        — optional `source` filter (only meaningful for scans).
      collection    — target Mongo collection name; defaults to scans.
      vector_index  — Atlas vectorSearch index name on `collection`.
      text_index    — Atlas Search index name on `collection`.
      text_paths    — list of fields the text query searches.
      embedding_text — optional override of what to embed (defaults to `q`).
    """
    if not q or not q.strip():
        return []

    target_coll = collection or C.SCANS
    cfg = _resolve_config(
        target_coll,
        vector_index=vector_index,
        text_index=text_index,
        text_paths=text_paths,
    )

    if not using_mock():
        try:
            return _rankfusion_pipeline(
                q,
                k=k,
                vector_weight=vector_weight,
                text_weight=text_weight,
                source=source,
                cfg=cfg,
                embedding_text=embedding_text,
            )
        except OperationFailure as e:
            logger.warning("$rankFusion failed (%s) — falling back to manual RRF", e)
        except Exception as e:
            logger.warning("$rankFusion error (%s) — falling back to manual RRF", e)

    return _manual_rrf(
        q,
        k=k,
        vector_weight=vector_weight,
        text_weight=text_weight,
        source=source,
        cfg=cfg,
        embedding_text=embedding_text,
    )


# ── Per-collection config registry ─────────────────────────────────────────
def _resolve_config(
    collection: str,
    *,
    vector_index: Optional[str],
    text_index: Optional[str],
    text_paths: Optional[list[str]],
) -> dict:
    """Build the search-config dict, defaulting unspecified fields per
    collection. Adding a new collection just means appending an entry here."""
    defaults = {
        C.SCANS: {
            "vector_index": _SCANS_VECTOR_INDEX,
            "text_index": SEARCH_INDEX_NAME,
            "text_paths": ["input_text", "findings.title", "findings.evidence"],
            "project": {
                "input_text": 1,
                "risk_score": 1,
                "findings": 1,
                "source": 1,
                "github": 1,
                "created_at": 1,
            },
            "supports_source_filter": True,
        },
        C.AGENT_TOOLS: {
            "vector_index": "agent_tools_vector_idx",
            "text_index": "agent_tools_text_idx",
            "text_paths": [
                "tool_name",
                "evidence_samples",
                "framework",
                "capabilities",
            ],
            "project": {
                "tool_name": 1,
                "repo_full_name": 1,
                "framework": 1,
                "capabilities": 1,
                "missing_safeguards": 1,
                "risk_score": 1,
                "risk_level": 1,
                "owasp": 1,
                "occurrences": 1,
                "evidence_samples": 1,
                "first_seen_at": 1,
                "last_seen_at": 1,
            },
            "supports_source_filter": False,
        },
    }
    cfg = dict(defaults.get(collection) or {})
    cfg["collection"] = collection
    if vector_index:
        cfg["vector_index"] = vector_index
    if text_index:
        cfg["text_index"] = text_index
    if text_paths:
        cfg["text_paths"] = text_paths
    cfg.setdefault("project", {})
    cfg.setdefault(
        "supports_source_filter", cfg.get("collection") == C.SCANS
    )
    return cfg


# ── Atlas-native $rankFusion pipeline ───────────────────────────────────────
def _rankfusion_pipeline(
    q: str,
    *,
    k: int,
    vector_weight: float,
    text_weight: float,
    source: Optional[str],
    cfg: dict,
    embedding_text: Optional[str],
) -> list[dict]:
    qvec = embed(embedding_text or q, input_type="query")
    project = {**cfg.get("project", {}), "fusion_score": {"$meta": "scoreDetails"}}
    pipeline: list[dict] = [
        {
            "$rankFusion": {
                "input": {
                    "pipelines": {
                        "vector": [
                            {
                                "$vectorSearch": {
                                    "index": cfg["vector_index"],
                                    "path": "embedding",
                                    "queryVector": qvec,
                                    "numCandidates": 200,
                                    "limit": k * 3,
                                }
                            }
                        ],
                        "text": [
                            {
                                "$search": {
                                    "index": cfg["text_index"],
                                    "text": {
                                        "query": q,
                                        "path": cfg["text_paths"],
                                        "fuzzy": {"maxEdits": 1},
                                    },
                                }
                            },
                            {"$limit": k * 3},
                        ],
                    }
                },
                "combination": {
                    "weights": {"vector": vector_weight, "text": text_weight}
                },
                "scoreDetails": True,
            }
        },
        {"$limit": k},
        {"$project": project},
    ]
    if source and cfg.get("supports_source_filter"):
        pipeline.insert(1, {"$match": {"source": source}})
    return list(col(cfg["collection"]).aggregate(pipeline))


# ── Manual reciprocal-rank-fusion fallback ──────────────────────────────────
def _manual_rrf(
    q: str,
    *,
    k: int,
    vector_weight: float,
    text_weight: float,
    source: Optional[str],
    cfg: dict,
    embedding_text: Optional[str],
) -> list[dict]:
    """Pure-Python Reciprocal Rank Fusion. Same formula Atlas uses:
    score(doc) = sum_over_lists( weight_l / (60 + rank_l(doc)) )

    Two ranked lists feed the fusion:
      • Vector list — for SCANS we reuse the prompt corpus index (so we can
        rank scans by similarity to known prompts even without scans
        carrying their own embedding). For other collections we do a flat
        cosine over docs that carry their own `embedding` field.
      • Text list — Atlas $search if available; otherwise a regex scan over
        the configured `text_paths`.
    """
    qvec = embed(embedding_text or q, input_type="query")
    target = cfg["collection"]

    if target == C.SCANS:
        vec_docs = _vector_list_for_scans(qvec, k=k * 3)
        try:
            text_docs = (
                _atlas_search(q, limit=k * 3, source=source)
                if not using_mock()
                else _regex_fallback(q, limit=k * 3, source=source)
            )
        except Exception:
            text_docs = _regex_fallback(q, limit=k * 3, source=source)
    else:
        vec_docs = _vector_list_for_collection(target, qvec, k=k * 3)
        text_docs = _regex_for_collection(
            target, q, paths=cfg["text_paths"], limit=k * 3
        )

    K_CONSTANT = 60.0
    scores: dict = {}
    docs: dict = {}

    def _id(d: dict) -> str:
        return str(d.get("_id"))

    for rank, d in enumerate(vec_docs):
        scores[_id(d)] = scores.get(_id(d), 0.0) + vector_weight / (
            K_CONSTANT + rank + 1
        )
        docs[_id(d)] = d
    for rank, d in enumerate(text_docs):
        scores[_id(d)] = scores.get(_id(d), 0.0) + text_weight / (
            K_CONSTANT + rank + 1
        )
        docs[_id(d)] = d

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:k]
    out = []
    for did, score in ranked:
        d = dict(docs[did])
        d["fusion_score"] = score
        out.append(d)
    return out


def _vector_list_for_scans(qvec: list[float], *, k: int) -> list[dict]:
    """Reuse the prompt-vectors corpus to rank scans by topical similarity."""
    try:
        if not using_mock():
            vec_hits = _vec_search(qvec, k=k, num_candidates=100, min_score=0.0)
        else:
            vec_hits = _local_search(qvec, k=k, min_score=0.0)
    except Exception:
        vec_hits = _local_search(qvec, k=k, min_score=0.0)
    matched_texts = [h["text"] for h in vec_hits]
    if not matched_texts:
        return []
    return list(
        col(C.SCANS).find({"input_text": {"$in": matched_texts}}).limit(k)
    )


def _vector_list_for_collection(
    collection: str, qvec: list[float], *, k: int
) -> list[dict]:
    """Flat cosine over docs that carry an `embedding` field."""
    out: list[tuple[float, dict]] = []
    for doc in col(collection).find({"embedding": {"$exists": True}}):
        emb = doc.get("embedding") or []
        if not emb:
            continue
        score = cosine(qvec, emb)
        out.append((score, doc))
    out.sort(key=lambda t: t[0], reverse=True)
    return [d for _, d in out[:k]]


def _regex_for_collection(
    collection: str, q: str, *, paths: list[str], limit: int
) -> list[dict]:
    """Case-insensitive regex OR over the configured text paths.

    Cheap fallback when Atlas $search isn't available — keeps the API
    contract identical so the frontend can rely on `fusion_score`.
    """
    if not paths:
        return []
    import re as _re

    pattern = {"$regex": _re.escape(q), "$options": "i"}
    or_clauses = [{p: pattern} for p in paths]
    return list(col(collection).find({"$or": or_clauses}).limit(limit))
