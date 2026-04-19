"""MongoDB Atlas client + collection registry.

Single entry point for both async (Motor) and sync (PyMongo) access. Tests use
mongomock automatically when no MONGODB_URI is configured.

Design notes:
- We expose *both* async and sync handles. The new `/api/scan/v2`, change-stream
  WebSocket, and Vector Search code is async (Motor). The legacy synchronous
  scan path stays on PyMongo for the cutover window so we don't have to rewrite
  every router in one shot.
- Collection names are centralized here so a typo in one router can't silently
  read from a phantom collection.
- `init_collections()` is idempotent and:
    * creates the time-series `risk_snapshots` collection if missing
    * applies $jsonSchema validators where we want them
    * builds standard btree indexes (the Search/Vector indexes are managed
      separately via setup_atlas_indexes.py because they're Atlas-only)
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import CollectionInvalid, OperationFailure

from config import settings

logger = logging.getLogger("promptshield.mongo")


# ── Collection name registry ────────────────────────────────────────────────
class C:
    SCANS = "scans"
    AUDIT_LOGS = "audit_logs"
    RISK_SNAPSHOTS = "risk_snapshots"  # time-series collection
    FINDING_RECORDS = "finding_records"
    FINDING_SUPPRESSIONS = "finding_suppressions"
    USERS = "users"
    ORGANIZATIONS = "organizations"  # embeds members + api_keys
    POLICY_VERSIONS = "policy_versions"
    SCAN_JOBS = "scan_jobs"
    EVAL_RUNS = "eval_runs"
    BASELINE_FINDINGS = "baseline_findings"
    DEPENDENCIES = "dependencies"
    INTEGRATION_EVENTS = "integration_events"
    GRAPH_NODES = "graph_nodes"
    GRAPH_EDGES = "graph_edges"
    RISK_ACCEPTANCES = "risk_acceptances"
    FINDING_RECORD_EVENTS = "finding_record_events"

    # ── Atlas-unique collections ────────────────────────────────────────────
    PROMPT_VECTORS = "prompt_vectors"  # corpus seeded from prompts.json
    BENCHMARK_RUNS = "benchmark_runs"  # historical eval results

    # ── Agentic-security collections (v0.5+) ────────────────────────────────
    # Tool registry: one row per (repo, tool_name) — derived from agentic
    # findings on every scan. Powers the "agent attack surface" view.
    AGENT_TOOLS = "agent_tools"
    # Curated knowledge base of known dangerous tool patterns + their CVEs /
    # exploit references. Atlas Vector Search index sits on top of this so
    # we can match new tools to historical exploits.
    AGENT_EXPLOIT_CORPUS = "agent_exploit_corpus"
    # Critical agentic findings get cross-posted here so an Atlas Trigger
    # (or an external SIEM tail) can fan out alerts. Backfilled by Python
    # too so the demo works without trigger setup.
    AGENT_ALERTS = "agent_alerts"
    # Time-series snapshot of agent attack surface size per scan.
    AGENT_SURFACE_TIMELINE = "agent_surface_timeline"
    # Connected coding-agent identities for attribution in dashboard/agents UI.
    AGENT_ACCOUNTS = "agent_accounts"


# ── Lazy singletons ─────────────────────────────────────────────────────────
_lock = threading.Lock()
_sync_client: Optional[MongoClient] = None
_async_client = None  # motor.motor_asyncio.AsyncIOMotorClient
_using_mock = False


def _mongo_tls_kwargs() -> dict:
    """PyMongo TLS options. Atlas uses a public CA chain; many Python installs
    on macOS fail with CERTIFICATE_VERIFY_FAILED unless we pin tlsCAFile to
    certifi's bundle (Install Certificates.command fixes python.org builds only)."""
    if settings.MONGODB_TLS_ALLOW_INVALID:
        return {"tlsAllowInvalidCertificates": True}
    if settings.MONGODB_TLS_CA_FILE:
        return {"tlsCAFile": settings.MONGODB_TLS_CA_FILE}
    try:
        import certifi

        return {"tlsCAFile": certifi.where()}
    except ImportError:
        logger.warning(
            "certifi not installed — Mongo TLS may fail on macOS. "
            "`pip install certifi` or set MONGODB_TLS_CA_FILE to a PEM bundle."
        )
        return {}


def _build_sync_client() -> MongoClient:
    """Build a sync PyMongo client, falling back to mongomock when no URI."""
    global _using_mock
    uri = settings.MONGODB_URI
    if not uri:
        try:
            import mongomock

            _using_mock = True
            logger.info("MONGODB_URI not set — using in-process mongomock")
            return mongomock.MongoClient()
        except ImportError as e:
            raise RuntimeError(
                "MONGODB_URI is not set and mongomock is not installed. "
                "Either set MONGODB_URI in backend/.env or `pip install mongomock`."
            ) from e
    kw = {
        "serverSelectionTimeoutMS": 8000,
        "appname": "promptshield",
        **_mongo_tls_kwargs(),
    }
    return MongoClient(uri, **kw)


def get_client() -> MongoClient:
    global _sync_client
    if _sync_client is None:
        with _lock:
            if _sync_client is None:
                _sync_client = _build_sync_client()
    return _sync_client


def get_db() -> Database:
    return get_client()[settings.MONGODB_DB]


def col(name: str) -> Collection:
    return get_db()[name]


def using_mock() -> bool:
    """True iff we fell back to mongomock (i.e. no real MONGODB_URI)."""
    return _using_mock


# ── Async (Motor) ────────────────────────────────────────────────────────────
def get_async_client():
    """Lazily build a Motor client. Imported here to avoid forcing motor on
    sync-only test environments that don't have an event loop."""
    global _async_client
    if _async_client is None:
        with _lock:
            if _async_client is None:
                if not settings.MONGODB_URI:
                    # Async path requires a real cluster; mongomock has no asyncio.
                    return None
                from motor.motor_asyncio import AsyncIOMotorClient

                _async_client = AsyncIOMotorClient(
                    settings.MONGODB_URI,
                    serverSelectionTimeoutMS=8000,
                    appname="promptshield-async",
                    **_mongo_tls_kwargs(),
                )
    return _async_client


def get_async_db():
    client = get_async_client()
    return client[settings.MONGODB_DB] if client is not None else None


def acol(name: str):
    db = get_async_db()
    return db[name] if db is not None else None


# ── Schema validators (only the ones worth enforcing) ───────────────────────
SCANS_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["created_at", "source", "risk_score", "findings", "counts"],
        "properties": {
            "created_at": {"bsonType": "date"},
            "source": {"enum": ["web", "github", "api", "demo"]},
            "risk_score": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 100},
            "findings": {"bsonType": "array"},
            "counts": {
                "bsonType": "object",
                "required": ["static", "ai", "total"],
                "properties": {
                    "static": {"bsonType": "int", "minimum": 0},
                    "ai": {"bsonType": "int", "minimum": 0},
                    "total": {"bsonType": "int", "minimum": 0},
                },
            },
            "input_text": {"bsonType": "string"},
            "llm_targets": {"bsonType": "array"},
            "github": {"bsonType": ["object", "null"]},
        },
    }
}

# Audit log: actor + action are required; everything else is contextual.
AUDIT_LOGS_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["created_at", "actor", "action"],
        "properties": {
            "created_at": {"bsonType": "date"},
            "actor": {"bsonType": "string", "minLength": 1},
            "action": {"bsonType": "string", "minLength": 1, "maxLength": 64},
            "source": {"enum": ["web", "github", "api", "demo", "system"]},
            "repo_full_name": {"bsonType": ["string", "null"]},
            "scan_id": {"bsonType": ["string", "objectId", "int", "null"]},
            "details": {"bsonType": ["object", "null"]},
        },
    }
}

# Risk snapshot (time-series): bucketed by source. We keep this loose because
# Atlas time-series collections are stricter about top-level shape than
# regular collections.
RISK_SNAPSHOTS_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["ts", "risk_score"],
        "properties": {
            "ts": {"bsonType": "date"},
            "risk_score": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 100},
            "scan_count": {"bsonType": ["int", "long"], "minimum": 0},
            "critical_count": {"bsonType": ["int", "long"], "minimum": 0},
            "high_count": {"bsonType": ["int", "long"], "minimum": 0},
            "medium_count": {"bsonType": ["int", "long"], "minimum": 0},
            "low_count": {"bsonType": ["int", "long"], "minimum": 0},
            "meta": {"bsonType": ["object", "null"]},
        },
    }
}

# Agent tools registry: one document per AI-exposed function we observed
# in scanned code. Schema is loose because tool metadata varies wildly across
# frameworks (LangChain Tool, MCP @tool, OpenAI tools=[], CrewAI agent.tool…)
# but we lock the keys we actually query.
AGENT_TOOLS_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["tool_name", "first_seen_at", "last_seen_at"],
        "properties": {
            "tool_name": {"bsonType": "string", "minLength": 1, "maxLength": 200},
            "repo_full_name": {"bsonType": ["string", "null"]},
            "framework": {"bsonType": ["string", "null"]},
            "capabilities": {"bsonType": ["array", "null"]},
            "missing_safeguards": {"bsonType": ["array", "null"]},
            "risk_score": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 100},
            "risk_level": {"enum": ["critical", "high", "medium", "low"]},
            "first_seen_at": {"bsonType": "date"},
            "last_seen_at": {"bsonType": "date"},
            "occurrences": {"bsonType": ["int", "long"], "minimum": 1},
            "embedding": {"bsonType": ["array", "null"]},
        },
    }
}

# Agent surface timeline: snapshot per scan, keyed by repo when available
# (or by source for ad-hoc web scans). Time-series collection in Atlas;
# regular collection on mongomock.
AGENT_SURFACE_TIMELINE_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["ts"],
        "properties": {
            "ts": {"bsonType": "date"},
            "tool_count": {"bsonType": ["int", "long"], "minimum": 0},
            "critical_tool_count": {"bsonType": ["int", "long"], "minimum": 0},
            "unsafe_output_count": {"bsonType": ["int", "long"], "minimum": 0},
            "rag_unsanitized_count": {"bsonType": ["int", "long"], "minimum": 0},
            "agent_risk_score": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 100},
            "meta": {"bsonType": ["object", "null"]},
        },
    }
}

# Benchmark runs power the model-registry view. Locked-down so a bad CI run
# can't write garbage into the registry.
BENCHMARK_RUNS_SCHEMA = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["ts", "accuracy", "precision", "recall", "f1", "sample_count"],
        "properties": {
            "ts": {"bsonType": "date"},
            "accuracy": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 1},
            "precision": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 1},
            "recall": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 1},
            "f1": {"bsonType": ["double", "int"], "minimum": 0, "maximum": 1},
            "sample_count": {"bsonType": ["int", "long"], "minimum": 1},
            "confusion_matrix": {"bsonType": ["object", "null"]},
            "layers_enabled": {"bsonType": ["array", "null"]},
            "model_id": {"bsonType": ["string", "objectId", "null"]},
            "notes": {"bsonType": ["string", "null"]},
        },
    }
}


# ── Init / migration ────────────────────────────────────────────────────────
def _create_or_relax(db: Database, name: str, validator: dict | None, **opts) -> None:
    """Create a collection if missing. mongomock ignores most options gracefully."""
    if name in db.list_collection_names():
        if validator and not _using_mock:
            try:
                db.command({"collMod": name, "validator": validator, "validationLevel": "moderate"})
            except OperationFailure as e:
                logger.warning("collMod failed for %s: %s", name, e)
        return
    try:
        kwargs = dict(opts)
        if validator and not _using_mock:
            kwargs["validator"] = validator
        db.create_collection(name, **kwargs)
    except CollectionInvalid:
        pass
    except OperationFailure as e:
        logger.warning("create_collection failed for %s: %s — falling back to plain", name, e)
        db.create_collection(name)


def init_collections() -> None:
    """Idempotent: ensure collections + btree indexes exist.

    Atlas Search and Vector Search indexes are *not* created here — they are
    Atlas-only and managed by `scripts/setup_atlas_indexes.py` so this function
    keeps working under mongomock.
    """
    db = get_db()

    # scans — schema-validated
    _create_or_relax(db, C.SCANS, SCANS_SCHEMA)

    # risk_snapshots — Atlas time-series (skipped on mongomock; falls back to plain)
    if C.RISK_SNAPSHOTS not in db.list_collection_names():
        try:
            db.create_collection(
                C.RISK_SNAPSHOTS,
                timeseries={
                    "timeField": "ts",
                    "metaField": "meta",
                    "granularity": "hours",
                },
                expireAfterSeconds=60 * 60 * 24 * 365,  # 1 year TTL
            )
            logger.info("Created time-series collection: %s", C.RISK_SNAPSHOTS)
        except (OperationFailure, TypeError, NotImplementedError) as e:
            logger.info("Time-series unavailable (%s) — using regular collection", e)
            try:
                db.create_collection(C.RISK_SNAPSHOTS)
            except CollectionInvalid:
                pass

    # Validated collections — soft schema discipline that won't break demo writes.
    _create_or_relax(db, C.AUDIT_LOGS, AUDIT_LOGS_SCHEMA)
    _create_or_relax(db, C.BENCHMARK_RUNS, BENCHMARK_RUNS_SCHEMA)
    _create_or_relax(db, C.AGENT_TOOLS, AGENT_TOOLS_SCHEMA)

    # Agent surface timeline — Atlas time-series; falls back to plain like
    # risk_snapshots. Keep this BEFORE the AUDIT_LOGS validator block so it
    # exists when the validator pass runs further down.
    if C.AGENT_SURFACE_TIMELINE not in db.list_collection_names():
        try:
            db.create_collection(
                C.AGENT_SURFACE_TIMELINE,
                timeseries={
                    "timeField": "ts",
                    "metaField": "meta",
                    "granularity": "hours",
                },
                expireAfterSeconds=60 * 60 * 24 * 365,
            )
            logger.info("Created time-series collection: %s", C.AGENT_SURFACE_TIMELINE)
        except (OperationFailure, TypeError, NotImplementedError) as e:
            logger.info(
                "Time-series unavailable for %s (%s) — using regular collection",
                C.AGENT_SURFACE_TIMELINE,
                e,
            )
            try:
                db.create_collection(C.AGENT_SURFACE_TIMELINE)
            except CollectionInvalid:
                pass

    # Apply validator only when the regular-collection fallback is in use
    # (Atlas blocks validators on time-series collections).
    if (
        C.AGENT_SURFACE_TIMELINE in db.list_collection_names()
        and not _using_mock
    ):
        try:
            opts = db[C.AGENT_SURFACE_TIMELINE].options() or {}
            if "timeseries" not in opts:
                db.command(
                    {
                        "collMod": C.AGENT_SURFACE_TIMELINE,
                        "validator": AGENT_SURFACE_TIMELINE_SCHEMA,
                        "validationLevel": "moderate",
                    }
                )
        except OperationFailure as e:
            logger.info("collMod skipped for %s: %s", C.AGENT_SURFACE_TIMELINE, e)
    # risk_snapshots is time-series in Atlas (validators not supported on
    # time-series collections per server-side restriction; on a regular
    # fallback collection we apply the validator).
    if C.RISK_SNAPSHOTS in db.list_collection_names() and not _using_mock:
        try:
            opts = db[C.RISK_SNAPSHOTS].options() or {}
            if "timeseries" not in opts:
                db.command(
                    {
                        "collMod": C.RISK_SNAPSHOTS,
                        "validator": RISK_SNAPSHOTS_SCHEMA,
                        "validationLevel": "moderate",
                    }
                )
        except OperationFailure as e:
            logger.info("collMod skipped for %s: %s", C.RISK_SNAPSHOTS, e)

    # All other collections — plain
    for name in [
        C.FINDING_RECORDS,
        C.FINDING_SUPPRESSIONS,
        C.USERS,
        C.ORGANIZATIONS,
        C.POLICY_VERSIONS,
        C.SCAN_JOBS,
        C.EVAL_RUNS,
        C.BASELINE_FINDINGS,
        C.DEPENDENCIES,
        C.INTEGRATION_EVENTS,
        C.GRAPH_NODES,
        C.GRAPH_EDGES,
        C.RISK_ACCEPTANCES,
        C.FINDING_RECORD_EVENTS,
        C.PROMPT_VECTORS,
        C.AGENT_EXPLOIT_CORPUS,
        C.AGENT_ALERTS,
        C.AGENT_ACCOUNTS,
    ]:
        _create_or_relax(db, name, None)

    # ── Btree indexes ───────────────────────────────────────────────────────
    db[C.SCANS].create_index([("source", ASCENDING), ("created_at", DESCENDING)])
    db[C.SCANS].create_index([("github.repo_full_name", ASCENDING), ("created_at", DESCENDING)])
    db[C.SCANS].create_index([("github.author_login", ASCENDING)])
    db[C.SCANS].create_index([("created_at", DESCENDING)])

    db[C.AUDIT_LOGS].create_index([("created_at", DESCENDING)])
    db[C.AUDIT_LOGS].create_index([("action", ASCENDING), ("created_at", DESCENDING)])
    db[C.AUDIT_LOGS].create_index([("repo_full_name", ASCENDING), ("created_at", DESCENDING)])

    db[C.FINDING_RECORDS].create_index(
        [("signature", ASCENDING), ("repo_full_name", ASCENDING)], unique=True
    )
    db[C.FINDING_RECORDS].create_index([("repo_full_name", ASCENDING), ("status", ASCENDING)])
    db[C.FINDING_RECORDS].create_index([("sla_due_at", ASCENDING), ("status", ASCENDING)])

    db[C.FINDING_SUPPRESSIONS].create_index(
        [("signature", ASCENDING), ("repo_full_name", ASCENDING)], unique=True
    )

    db[C.USERS].create_index([("email", ASCENDING)], unique=True)
    db[C.ORGANIZATIONS].create_index([("slug", ASCENDING)], unique=True)

    db[C.PROMPT_VECTORS].create_index([("category", ASCENDING)])
    db[C.PROMPT_VECTORS].create_index([("expected", ASCENDING)])

    db[C.BENCHMARK_RUNS].create_index([("ts", DESCENDING)])
    db[C.EVAL_RUNS].create_index([("run_at", DESCENDING)])

    # ── Agentic-security indexes ──────────────────────────────────────────
    # (repo, tool_name) is the natural key — upserts dedupe on it.
    db[C.AGENT_TOOLS].create_index(
        [("repo_full_name", ASCENDING), ("tool_name", ASCENDING)], unique=True
    )
    db[C.AGENT_TOOLS].create_index([("risk_level", ASCENDING), ("last_seen_at", DESCENDING)])
    db[C.AGENT_TOOLS].create_index([("framework", ASCENDING)])
    db[C.AGENT_TOOLS].create_index([("capabilities", ASCENDING)])

    db[C.AGENT_EXPLOIT_CORPUS].create_index([("category", ASCENDING)])
    db[C.AGENT_EXPLOIT_CORPUS].create_index([("framework", ASCENDING)])

    db[C.AGENT_ALERTS].create_index([("created_at", DESCENDING)])
    db[C.AGENT_ALERTS].create_index([("repo_full_name", ASCENDING), ("created_at", DESCENDING)])
    db[C.AGENT_ALERTS].create_index([("acknowledged", ASCENDING)])
    db[C.AGENT_ACCOUNTS].create_index(
        [("provider", ASCENDING), ("github_handle", ASCENDING), ("repo_scope", ASCENDING)],
        unique=True,
    )
    db[C.AGENT_ACCOUNTS].create_index([("created_at", DESCENDING)])

    # Time-series collections don't need a separate ts index (Atlas builds one),
    # but mongomock fallback collections benefit from one.
    if _using_mock:
        db[C.AGENT_SURFACE_TIMELINE].create_index([("ts", DESCENDING)])

    logger.info("init_collections: done (mock=%s)", _using_mock)


def health() -> dict:
    """Quick liveness probe used by /api/health."""
    try:
        get_client().admin.command("ping")
        return {"ok": True, "db": settings.MONGODB_DB, "mock": _using_mock}
    except Exception as e:
        return {"ok": False, "error": str(e), "mock": _using_mock}
