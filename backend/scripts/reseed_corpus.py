"""Wipe `prompt_vectors` and re-embed the corpus from scratch.

Run this whenever you switch EMBEDDING_PROVIDER or EMBEDDING_MODEL — the
existing vectors won't match the new dimensionality and Atlas Vector Search
will silently return zero hits.

    python backend/scripts/reseed_corpus.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve()
BACKEND = HERE.parent.parent
sys.path.insert(0, str(BACKEND))

from config import settings  # noqa: E402
from mongo import C, col, init_collections  # noqa: E402
from vector_search import seed_corpus  # noqa: E402


def main() -> int:
    print(f"→ Reseeding corpus with {settings.EMBEDDING_PROVIDER}/{settings.EMBEDDING_MODEL} "
          f"({settings.EMBEDDING_DIMS} dims)")
    init_collections()
    deleted = col(C.PROMPT_VECTORS).delete_many({}).deleted_count
    print(f"  cleared {deleted} existing vectors")
    res = seed_corpus(force=True)
    print(f"  seeded: {res}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
