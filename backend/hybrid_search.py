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
from vector_search import _atlas_search as _vec_search, _local_search

# Scans carry their own embedding — hybrid search stays on one collection.
_SCANS_VECTOR_INDEX = "scans_vector_idx"

logger = logging.getLogger("promptshield.hybrid_search")


def hybrid_search(
    q: str,
    *,
    k: int = 20,
    vector_weight: float = 1.0,
    text_weight: float = 1.0,
    source: Optional[str] = None,
) -> list[dict]:
    """Top-k scans matching `q` via fused semantic + lexical search."""
    if not q or not q.strip():
        return []

    if not using_mock():
        try:
            return _rankfusion_pipeline(
                q, k=k, vector_weight=vector_weight, text_weight=text_weight, source=source,
            )
        except OperationFailure as e:
            logger.warning("$rankFusion failed (%s) — falling back to manual RRF", e)
        except Exception as e:
            logger.warning("$rankFusion error (%s) — falling back to manual RRF", e)

    return _manual_rrf(q, k=k, vector_weight=vector_weight, text_weight=text_weight, source=source)


# ── Atlas-native $rankFusion pipeline ───────────────────────────────────────
def _rankfusion_pipeline(
    q: str,
    *,
    k: int,
    vector_weight: float,
    text_weight: float,
    source: Optional[str],
) -> list[dict]:
    qvec = embed(q, input_type="query")
    # Both pipelines run on the SCANS collection (required by $rankFusion).
    # $vectorSearch uses scans_vector_idx (scan documents carry their own
    # embeddings); $search uses scans_text_idx (Lucene full-text).
    pipeline: list[dict] = [
        {
            "$rankFusion": {
                "input": {
                    "pipelines": {
                        "vector": [
                            {
                                "$vectorSearch": {
                                    "index": _SCANS_VECTOR_INDEX,
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
                                    "index": SEARCH_INDEX_NAME,
                                    "text": {
                                        "query": q,
                                        "path": [
                                            "input_text",
                                            "findings.title",
                                            "findings.evidence",
                                        ],
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
        {
            "$project": {
                "input_text": 1,
                "risk_score": 1,
                "findings": 1,
                "source": 1,
                "github": 1,
                "created_at": 1,
                "fusion_score": {"$meta": "scoreDetails"},
            }
        },
    ]
    if source:
        pipeline.insert(1, {"$match": {"source": source}})
    return list(col(C.SCANS).aggregate(pipeline))


# ── Manual reciprocal-rank-fusion fallback ──────────────────────────────────
def _manual_rrf(
    q: str,
    *,
    k: int,
    vector_weight: float,
    text_weight: float,
    source: Optional[str],
) -> list[dict]:
    """Pure-Python Reciprocal Rank Fusion. Same formula Atlas uses:
    score(doc) = sum_over_lists( weight_l / (60 + rank_l(doc)) )"""
    qvec = embed(q, input_type="query")

    # Vector list — search the prompt corpus (small, fast) for similar prompts,
    # then surface scans whose `input_text` matches those prompts. This works
    # without a `scans.embedding` index, useful before full corpus build-out.
    try:
        if not using_mock():
            vec_hits = _vec_search(qvec, k=k * 3, num_candidates=100, min_score=0.0)
        else:
            vec_hits = _local_search(qvec, k=k * 3, min_score=0.0)
    except Exception:
        vec_hits = _local_search(qvec, k=k * 3, min_score=0.0)
    matched_texts = [h["text"] for h in vec_hits]
    vec_scans: list[dict] = []
    if matched_texts:
        vec_scans = list(
            col(C.SCANS)
            .find({"input_text": {"$in": matched_texts}})
            .limit(k * 3)
        )

    # Text list — Atlas $search if real cluster, else regex fallback.
    try:
        if not using_mock():
            text_scans = _atlas_search(q, limit=k * 3, source=source)
        else:
            text_scans = _regex_fallback(q, limit=k * 3, source=source)
    except Exception:
        text_scans = _regex_fallback(q, limit=k * 3, source=source)

    # RRF
    K_CONSTANT = 60.0
    scores: dict = {}
    docs: dict = {}

    def _id(d: dict) -> str:
        return str(d.get("_id"))

    for rank, d in enumerate(vec_scans):
        scores[_id(d)] = scores.get(_id(d), 0.0) + vector_weight / (K_CONSTANT + rank + 1)
        docs[_id(d)] = d
    for rank, d in enumerate(text_scans):
        scores[_id(d)] = scores.get(_id(d), 0.0) + text_weight / (K_CONSTANT + rank + 1)
        docs[_id(d)] = d

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:k]
    out = []
    for did, score in ranked:
        d = dict(docs[did])
        d["fusion_score"] = score
        out.append(d)
    return out
