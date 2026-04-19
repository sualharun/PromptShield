"""Embedding service.

Two backends, both behind one `embed(text)` interface:

  • EMBEDDING_PROVIDER=local  → sentence-transformers (all-MiniLM-L6-v2, 384d)
                                Runs on CPU, no network, no API key. Default.
  • EMBEDDING_PROVIDER=voyage → MongoDB-hosted Voyage AI Embedding API.
                                Higher quality. Needs VOYAGE_API_KEY and
                                hits https://ai.mongodb.com/v1/embeddings.

The output dimensionality is exposed as `EMBEDDING_DIMS` and *must* match the
`numDimensions` field of the Atlas Vector Search index. If you switch
providers, regenerate the index (see scripts/setup_atlas_indexes.py).

Design notes:
- `embed_many` batches because sentence-transformers is much faster on a batch
  than in a Python loop (~10x for our corpus size).
- Model is loaded lazily so importing this module is cheap (matters for tests
  + serverless cold-starts).
- Falls back to a deterministic hash-pseudo-embedding when both backends are
  unavailable, so unit tests never need network or torch installed. The hash
  embedding is NOT meaningful — it just keeps the pipeline runnable.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import threading
from typing import Iterable

from config import settings

logger = logging.getLogger("promptshield.embeddings")


_lock = threading.Lock()
_local_model = None
_dims = settings.EMBEDDING_DIMS


def dims() -> int:
    return _dims


# ── Local (sentence-transformers) ───────────────────────────────────────────
def _load_local():
    global _local_model, _dims
    if _local_model is not None:
        return _local_model
    with _lock:
        if _local_model is not None:
            return _local_model
        try:
            # Quiet HF download chatter unless the user opted in
            os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
            from sentence_transformers import SentenceTransformer

            logger.info("Loading sentence-transformers model: %s", settings.EMBEDDING_MODEL)
            _local_model = SentenceTransformer(settings.EMBEDDING_MODEL)
            _dims = int(_local_model.get_sentence_embedding_dimension())
            return _local_model
        except Exception as e:
            logger.warning("sentence-transformers unavailable (%s) — using hash fallback", e)
            return None


def _local_embed_many(texts: list[str]) -> list[list[float]]:
    model = _load_local()
    if model is None:
        return [_hash_embed(t) for t in texts]
    vecs = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
    return [list(map(float, v)) for v in vecs]


# ── Voyage AI (MongoDB's first-party embedding service) ────────────────────
# Direct Voyage endpoint. Models we care about (2026):
#   voyage-3-large    — flagship general-purpose, 1024 dims (best default)
#   voyage-3.5        — fast / cheap general-purpose, 1024 dims
#   voyage-code-3     — code-tuned, 1024 dims
#   voyage-context-3  — contextualized chunks, 1024 dims
# Voyage batches up to 128 inputs per request and returns L2-normalized vectors.
_VOYAGE_URL = "https://api.voyageai.com/v1/embeddings"
_VOYAGE_BATCH = 128


def _voyage_embed_many(texts: list[str], *, input_type: str = "document") -> list[list[float]]:
    import requests

    if not settings.VOYAGE_API_KEY:
        logger.warning("VOYAGE_API_KEY missing — falling back to local backend")
        return _local_embed_many(texts)

    headers = {
        "Authorization": f"Bearer {settings.VOYAGE_API_KEY}",
        "Content-Type": "application/json",
    }
    out: list[list[float]] = []
    global _dims
    for i in range(0, len(texts), _VOYAGE_BATCH):
        batch = texts[i : i + _VOYAGE_BATCH]
        payload = {
            "model": settings.EMBEDDING_MODEL or "voyage-3-large",
            "input": batch,
            "input_type": input_type,
        }
        # voyage-3-large supports configurable output_dimension {256,512,1024,2048}
        if settings.EMBEDDING_DIMS in (256, 512, 1024, 2048):
            payload["output_dimension"] = settings.EMBEDDING_DIMS
        try:
            r = requests.post(_VOYAGE_URL, json=payload, headers=headers, timeout=30)
            r.raise_for_status()
            data = r.json()
            vecs = [item["embedding"] for item in data["data"]]
            if vecs:
                _dims = len(vecs[0])
            out.extend(vecs)
        except Exception as e:
            logger.warning(
                "Voyage embed batch failed (%s) — falling back to local for this batch", e
            )
            out.extend(_local_embed_many(batch))
    return out


# ── Hash fallback (tests + dev with nothing installed) ──────────────────────
def _hash_embed(text: str) -> list[float]:
    """Deterministic 384-dim pseudo-embedding via SHA-256 expansion.

    NOT semantically meaningful. Only exists so the rest of the pipeline can
    run in environments without torch installed (CI, mongomock-only tests).
    """
    h = hashlib.sha256(text.encode("utf-8")).digest()
    # Expand to EMBEDDING_DIMS floats in [-1, 1] by chained hashing.
    out: list[float] = []
    seed = h
    while len(out) < _dims:
        seed = hashlib.sha256(seed).digest()
        for i in range(0, len(seed), 2):
            if len(out) >= _dims:
                break
            v = int.from_bytes(seed[i : i + 2], "big") / 65535.0
            out.append(v * 2.0 - 1.0)
    # L2-normalize so cosine == dot product.
    norm = math.sqrt(sum(x * x for x in out)) or 1.0
    return [x / norm for x in out]


# ── Public API ──────────────────────────────────────────────────────────────
def embed(text: str, *, input_type: str = "query") -> list[float]:
    """Embed a single string. `input_type` is honored by Voyage:
    `query` for live user input, `document` for corpus seeding."""
    return embed_many([text], input_type=input_type)[0]


def embed_many(texts: Iterable[str], *, input_type: str = "document") -> list[list[float]]:
    items = [t or "" for t in texts]
    if not items:
        return []
    if settings.EMBEDDING_PROVIDER == "voyage":
        return _voyage_embed_many(items, input_type=input_type)
    return _local_embed_many(items)


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (na * nb)
