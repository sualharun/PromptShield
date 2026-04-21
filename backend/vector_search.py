"""Atlas Vector Search integration — the headline feature.

What this module does:

  1) `seed_corpus()` reads backend/prompts.json (151 labeled attack prompts),
     embeds every prompt, and writes one document per prompt into
     `prompt_vectors`. Idempotent — re-running is a no-op until the corpus
     file changes.

  2) `find_similar(text, k=5)` runs an Atlas `$vectorSearch` against that
     corpus and returns the top-k semantic neighbors with scores. This is what
     the new `SEMANTIC_JAILBREAK_MATCH` finding in /api/scan is built from.

  3) `find_similar_local(text, k=5)` is the same query, but in pure Python
     using cosine similarity. Used as an automatic fallback when running
     against mongomock or before the Atlas Vector Search index is provisioned,
     so the demo path never hard-fails.

The Atlas-side index definition lives in `scripts/atlas_indexes/` and is
applied via `setup_atlas_indexes.py`. Index name: `prompt_vectors_idx`.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pymongo.errors import OperationFailure

from embeddings import cosine, embed, embed_many
from mongo import C, col, using_mock

logger = logging.getLogger("promptshield.vector_search")

VECTOR_INDEX_NAME = "prompt_vectors_idx"
PROMPTS_PATH = Path(__file__).resolve().parent / "prompts.json"


# ── Corpus seeding ──────────────────────────────────────────────────────────
def _load_corpus() -> list[dict]:
    if not PROMPTS_PATH.exists():
        logger.warning("prompts.json missing at %s — corpus will be empty", PROMPTS_PATH)
        return []
    with PROMPTS_PATH.open() as f:
        return json.load(f)


def seed_corpus(*, force: bool = False) -> dict:
    """Embed every prompt in prompts.json and upsert into prompt_vectors.

    Returns: { inserted, updated, skipped, total }.
    """
    corpus = _load_corpus()
    if not corpus:
        return {"inserted": 0, "updated": 0, "skipped": 0, "total": 0}

    coll = col(C.PROMPT_VECTORS)
    existing_count = coll.count_documents({})
    if existing_count >= len(corpus) and not force:
        logger.info("prompt_vectors already seeded (%d docs) — skipping", existing_count)
        return {"inserted": 0, "updated": 0, "skipped": existing_count, "total": existing_count}

    texts = [p["text"] for p in corpus]
    logger.info("Embedding %d prompts (this may take ~5-30s on first run)…", len(texts))
    vectors = embed_many(texts, input_type="document")

    inserted = updated = 0
    for prompt, vec in zip(corpus, vectors):
        doc = {
            "text": prompt["text"],
            "category": prompt.get("category", "uncategorized"),
            "expected": prompt.get("expected", "vulnerable"),
            "embedding": vec,
            "source": "prompts.json",
        }
        res = coll.update_one(
            {"text": prompt["text"]},
            {"$set": doc},
            upsert=True,
        )
        if res.upserted_id is not None:
            inserted += 1
        elif res.modified_count:
            updated += 1
    logger.info(
        "seed_corpus: inserted=%d updated=%d total=%d", inserted, updated, coll.count_documents({})
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": 0,
        "total": coll.count_documents({}),
    }


# ── Atlas $vectorSearch query ───────────────────────────────────────────────
def find_similar(
    text: str,
    *,
    k: int = 5,
    num_candidates: int = 100,
    min_score: float = 0.0,
) -> list[dict]:
    """Top-k semantic neighbors from the prompts corpus.

    Tries Atlas $vectorSearch first; falls back to in-process cosine if
    unavailable (mongomock, missing index, free-tier limitation). Either way,
    the route layer doesn't have to care.
    """
    if not text:
        return []
    qvec = embed(text, input_type="query")
    if not using_mock():
        try:
            return _atlas_search(qvec, k=k, num_candidates=num_candidates, min_score=min_score)
        except OperationFailure as e:
            logger.warning("$vectorSearch failed (%s) — falling back to local cosine", e)
        except Exception as e:
            logger.warning("$vectorSearch error (%s) — falling back to local cosine", e)
    return _local_search(qvec, k=k, min_score=min_score)


def _atlas_search(
    qvec: list[float], *, k: int, num_candidates: int, min_score: float
) -> list[dict]:
    pipeline = [
        {
            "$vectorSearch": {
                "index": VECTOR_INDEX_NAME,
                "path": "embedding",
                "queryVector": qvec,
                "numCandidates": num_candidates,
                "limit": k,
            }
        },
        {
            "$project": {
                "text": 1,
                "category": 1,
                "expected": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
        {"$match": {"score": {"$gte": min_score}}},
    ]
    return list(col(C.PROMPT_VECTORS).aggregate(pipeline))


def _local_search(qvec: list[float], *, k: int, min_score: float) -> list[dict]:
    """Pure-Python cosine over the whole corpus. Fine up to ~10k docs."""
    out: list[tuple[float, dict]] = []
    for doc in col(C.PROMPT_VECTORS).find({}, {"text": 1, "category": 1, "expected": 1, "embedding": 1}):
        emb = doc.get("embedding") or []
        if not emb:
            continue
        score = cosine(qvec, emb)
        if score >= min_score:
            out.append((score, doc))
    out.sort(key=lambda t: t[0], reverse=True)
    results: list[dict] = []
    for score, doc in out[:k]:
        results.append(
            {
                "_id": doc.get("_id"),
                "text": doc["text"],
                "category": doc.get("category"),
                "expected": doc.get("expected"),
                "score": float(score),
            }
        )
    return results


# ── Convenience: turn a vector hit into a Finding-shaped dict ───────────────
def to_finding(matches: list[dict], *, threshold: float = 0.78) -> Optional[dict]:
    """Convert the top vector-search hit into a `SEMANTIC_JAILBREAK_MATCH`
    finding, but only if it crossed the similarity threshold AND was labeled
    `vulnerable` in the corpus. Otherwise returns None (the prompt was
    semantically close to a *safe* example, which is not a finding)."""
    if not matches:
        return None
    top = matches[0]
    if top.get("expected") != "vulnerable":
        return None
    if float(top.get("score", 0)) < threshold:
        return None
    sev = "high" if top["score"] >= 0.88 else "medium"
    pct = int(round(top["score"] * 100))
    category = top.get("category", "attack")
    return {
        "type": "SEMANTIC_JAILBREAK_MATCH",
        "title": f"Semantic match to known {category} ({pct}% similar)",
        "severity": sev,
        "description": (
            f"Atlas Vector Search matched this prompt to a known "
            f"{category} pattern in our 151-prompt corpus with "
            f"{pct}% cosine similarity. Static rules missed it because "
            f"the wording differs from the original — but the embedding "
            f"shows the underlying intent is the same."
        ),
        "remediation": (
            "Treat this prompt as if it were the matched attack. "
            "Strip or escape user-controlled portions, add an instruction "
            "guard, and consider blocking inputs that match known-vulnerable "
            "vectors above 0.85 similarity."
        ),
        "source": "atlas_vector_search",
        "evidence": top["text"][:240],
        "cwe": "CWE-1039",
        "owasp": "LLM01",
        "confidence": float(top["score"]),
        "detector": "atlas_vector_search",
        "match": {
            "category": category,
            "score": float(top["score"]),
            "source_id": str(top.get("_id")) if top.get("_id") is not None else None,
        },
    }
