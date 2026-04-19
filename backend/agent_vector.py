"""Atlas Vector Search over the agent exploit corpus.

This is the second headline Atlas feature for the v0.5 agentic-security
pivot. Mechanically mirrors `vector_search.py` (corpus seeding + Atlas
$vectorSearch with a local-cosine fallback), but the corpus is curated
agentic exploit patterns rather than jailbreak prompts.

Why this matters for the demo:
  • Every scan can ask "is this newly detected tool semantically similar to
    a known dangerous pattern?" without the team writing a separate rule
    per pattern.
  • The corpus is small (~12 entries) but grows with the team — a
    knowledge base of historical agent-security incidents.
  • The vector index lives at backend/scripts/atlas_indexes/
    agent_exploit_corpus_idx.json and is auto-applied by
    setup_atlas_indexes.py because that script globs the whole directory.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pymongo.errors import OperationFailure

from embeddings import cosine, embed, embed_many
from mongo import C, col, using_mock

logger = logging.getLogger("promptshield.agent_vector")

VECTOR_INDEX_NAME = "agent_exploit_corpus_idx"
EXPLOITS_PATH = Path(__file__).resolve().parent / "agent_exploits.json"


# ── Corpus seeding ──────────────────────────────────────────────────────────
def _load_exploits() -> list[dict]:
    if not EXPLOITS_PATH.exists():
        logger.warning("agent_exploits.json missing at %s", EXPLOITS_PATH)
        return []
    with EXPLOITS_PATH.open() as f:
        return json.load(f)


def _embedding_text(exploit: dict) -> str:
    """Concatenate the fields that semantically describe the exploit, so a
    new tool's metadata (capabilities, evidence) can match against this
    composite description."""
    parts = [
        exploit.get("title", ""),
        exploit.get("pattern_text", ""),
        exploit.get("category", ""),
        exploit.get("framework", ""),
    ]
    return " ".join(p for p in parts if p)


def seed_exploit_corpus(*, force: bool = False) -> dict:
    """Embed and upsert every exploit pattern. Idempotent on (id)."""
    corpus = _load_exploits()
    if not corpus:
        return {"inserted": 0, "updated": 0, "skipped": 0, "total": 0}

    coll = col(C.AGENT_EXPLOIT_CORPUS)
    existing = coll.count_documents({})
    if existing >= len(corpus) and not force:
        return {"inserted": 0, "updated": 0, "skipped": existing, "total": existing}

    texts = [_embedding_text(e) for e in corpus]
    logger.info("Embedding %d agentic exploit patterns…", len(texts))
    vectors = embed_many(texts, input_type="document")

    inserted = updated = 0
    for exploit, vec in zip(corpus, vectors):
        doc = {**exploit, "embedding": vec, "embedding_text": _embedding_text(exploit)}
        res = coll.update_one({"id": exploit["id"]}, {"$set": doc}, upsert=True)
        if res.upserted_id is not None:
            inserted += 1
        elif res.modified_count:
            updated += 1
    total = coll.count_documents({})
    logger.info(
        "seed_exploit_corpus: inserted=%d updated=%d total=%d",
        inserted,
        updated,
        total,
    )
    return {"inserted": inserted, "updated": updated, "skipped": 0, "total": total}


# ── Query ──────────────────────────────────────────────────────────────────
def _query_text(
    *,
    tool_name: str,
    capabilities: list[str],
    framework: Optional[str],
    evidence: Optional[str],
) -> str:
    """Build the embedding-input string from a tool record."""
    return " ".join(
        filter(
            None,
            [
                f"tool {tool_name}",
                ("capabilities " + " ".join(capabilities)) if capabilities else "",
                f"framework {framework}" if framework else "",
                evidence or "",
            ],
        )
    )


def find_similar_exploits(
    *,
    tool_name: str,
    capabilities: list[str] | None = None,
    framework: Optional[str] = None,
    evidence: Optional[str] = None,
    k: int = 5,
    min_score: float = 0.0,
) -> list[dict]:
    """Top-k semantically similar exploits from the corpus.

    Tries Atlas $vectorSearch first; falls back to in-process cosine over
    the whole corpus. The corpus is small (~tens of docs) so the fallback
    is cheap.
    """
    capabilities = capabilities or []
    qtext = _query_text(
        tool_name=tool_name,
        capabilities=capabilities,
        framework=framework,
        evidence=evidence,
    )
    if not qtext.strip():
        return []
    qvec = embed(qtext, input_type="query")

    if not using_mock():
        try:
            return _atlas_search(qvec, k=k, min_score=min_score)
        except OperationFailure as e:
            logger.warning(
                "agent exploit $vectorSearch failed (%s) — falling back to local cosine",
                e,
            )
        except Exception as e:
            logger.warning(
                "agent exploit $vectorSearch error (%s) — falling back to local cosine",
                e,
            )
    return _local_search(qvec, k=k, min_score=min_score)


def _atlas_search(qvec: list[float], *, k: int, min_score: float) -> list[dict]:
    pipeline = [
        {
            "$vectorSearch": {
                "index": VECTOR_INDEX_NAME,
                "path": "embedding",
                "queryVector": qvec,
                "numCandidates": 50,
                "limit": k,
            }
        },
        {
            "$project": {
                "id": 1,
                "title": 1,
                "category": 1,
                "framework": 1,
                "severity": 1,
                "pattern_text": 1,
                "exploit_summary": 1,
                "cve_or_ref": 1,
                "remediation": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
        {"$match": {"score": {"$gte": min_score}}},
    ]
    return [_clean(d) for d in col(C.AGENT_EXPLOIT_CORPUS).aggregate(pipeline)]


def _local_search(qvec: list[float], *, k: int, min_score: float) -> list[dict]:
    out: list[tuple[float, dict]] = []
    for doc in col(C.AGENT_EXPLOIT_CORPUS).find({}):
        emb = doc.get("embedding") or []
        if not emb:
            continue
        score = cosine(qvec, emb)
        if score >= min_score:
            out.append((score, doc))
    out.sort(key=lambda t: t[0], reverse=True)
    results: list[dict] = []
    for score, doc in out[:k]:
        d = dict(doc)
        d["score"] = float(score)
        results.append(_clean(d))
    return results


def _clean(d: dict) -> dict:
    """Strip large fields before returning to API callers."""
    return {
        "id": d.get("id"),
        "title": d.get("title"),
        "category": d.get("category"),
        "framework": d.get("framework"),
        "severity": d.get("severity"),
        "pattern_text": d.get("pattern_text"),
        "exploit_summary": d.get("exploit_summary"),
        "cve_or_ref": d.get("cve_or_ref"),
        "remediation": d.get("remediation"),
        "score": float(d.get("score", 0)) if d.get("score") is not None else None,
    }
