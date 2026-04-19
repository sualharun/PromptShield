import os
import sys

# Make backend/ importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(__file__))

os.environ.setdefault("REDACT_PERSISTED_INPUT", "true")
os.environ.setdefault("SCAN_RATE_LIMIT", "1000")  # don't trip during tests

# ── MongoDB: use mongomock in tests (no MONGODB_URI -> automatic fallback) ─
# Atlas-only features ($vectorSearch, $search, $rankFusion, change streams)
# automatically degrade to in-process equivalents in mongomock so the unit
# test suite stays runnable without a network call. Integration tests that
# require a real Atlas cluster should set MONGODB_URI explicitly.
# Force-empty (not pop) so config.py's load_dotenv(override=False) doesn't
# re-populate MONGODB_URI from a developer's .env file.
os.environ["MONGODB_URI"] = ""
os.environ["MONGODB_DB"] = "promptshield_test"
os.environ.setdefault("PRIMARY_STORE", "mongo")
os.environ.setdefault("EMBEDDING_PROVIDER", "local")

from mongo import init_collections as _init_mongo_collections  # noqa: E402

try:
    _init_mongo_collections()
except Exception:
    # mongomock will silently skip Atlas-only features; soft-fail rather
    # than blow up the whole suite if a collection cannot be created.
    pass
