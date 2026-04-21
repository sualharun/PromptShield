"""GridFS-backed model registry — pairs with `benchmark_runs` for full MLOps story.

Why GridFS instead of a flat file:
  • Versioning: every upload gets a new ObjectId + metadata (sha256, size, tags)
  • Atlas-native: model artifact lives next to its eval metrics in the same cluster,
    no S3 bucket / artifact store to set up
  • Survives container restarts / serverless cold starts (no local filesystem state)
  • Audit-friendly: every download is a Mongo query you can monitor

Public surface:
  • upload_model(path, name, tags=...)        → uploaded ObjectId
  • download_model(name, *, version=None)     → bytes
  • load_pickle(name, *, version=None)        → unpickled object (cached)
  • list_models(name=None)                    → metadata for the registry UI
"""
from __future__ import annotations

import hashlib
import logging
import pickle
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import gridfs
from bson import ObjectId

from mongo import get_db, using_mock

logger = logging.getLogger("promptshield.model_registry")

_BUCKET_NAME = "model_registry"
_lock = threading.Lock()
_pickle_cache: dict[str, Any] = {}


def _bucket() -> gridfs.GridFS:
    """GridFS bucket scoped to a single name so Atlas indexes stay tidy."""
    return gridfs.GridFS(get_db(), collection=_BUCKET_NAME)


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


# ── Upload ──────────────────────────────────────────────────────────────────
def upload_model(
    path: str | Path,
    *,
    name: str,
    tags: Optional[dict] = None,
    description: Optional[str] = None,
) -> ObjectId:
    """Upload a model file (pickle, joblib, ONNX, anything) into GridFS.

    Re-uploading the *same* (name, sha256) is a no-op — returns the existing id.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Model file not found: {p}")
    data = p.read_bytes()
    digest = _sha256(data)

    fs = _bucket()
    existing = fs.find_one({"filename": name, "metadata.sha256": digest})
    if existing is not None:
        logger.info("upload_model: %s already at sha %s — reusing", name, digest[:12])
        return existing._id

    metadata = {
        "sha256": digest,
        "uploaded_at": datetime.now(timezone.utc),
        "size_bytes": len(data),
        "source_path": str(p),
        "tags": tags or {},
        "description": description,
    }
    return fs.put(data, filename=name, metadata=metadata)


# ── Download ────────────────────────────────────────────────────────────────
def _resolve(name: str, version: Optional[Any]) -> Optional[gridfs.GridOut]:
    fs = _bucket()
    if version is not None:
        # version may be an ObjectId, a hex string, or a sha256 prefix
        try:
            return fs.get(ObjectId(str(version)))
        except Exception:
            doc = fs.find_one({"filename": name, "metadata.sha256": str(version)})
            return doc
    # latest by upload time
    cursor = fs.find({"filename": name}).sort("uploadDate", -1).limit(1)
    docs = list(cursor)
    return docs[0] if docs else None


def download_model(name: str, *, version: Optional[Any] = None) -> Optional[bytes]:
    grid_out = _resolve(name, version)
    if grid_out is None:
        return None
    return grid_out.read()


def load_pickle(
    name: str,
    *,
    version: Optional[Any] = None,
    fallback_path: Optional[str | Path] = None,
) -> Any:
    """Unpickle a model from GridFS, with an optional filesystem fallback.

    Cached in-process so we don't repeatedly hit Atlas during a request loop.
    """
    cache_key = f"{name}@{version or 'latest'}"
    if cache_key in _pickle_cache:
        return _pickle_cache[cache_key]
    with _lock:
        if cache_key in _pickle_cache:
            return _pickle_cache[cache_key]
        try:
            blob = download_model(name, version=version)
            if blob is not None:
                obj = pickle.loads(blob)
                _pickle_cache[cache_key] = obj
                logger.info("load_pickle: served %s from GridFS (%d bytes)", name, len(blob))
                return obj
        except Exception as e:
            logger.warning("load_pickle: GridFS read failed for %s (%s)", name, e)
        # Filesystem fallback (dev / cold-start before first upload)
        if fallback_path:
            p = Path(fallback_path)
            if p.exists():
                obj = pickle.loads(p.read_bytes())
                _pickle_cache[cache_key] = obj
                logger.info("load_pickle: served %s from filesystem fallback", name)
                # Best-effort backfill into GridFS so subsequent loads are Atlas-native
                if not using_mock():
                    try:
                        upload_model(p, name=name, tags={"backfilled": True})
                    except Exception as e:
                        logger.info("load_pickle: backfill upload skipped (%s)", e)
                return obj
        raise FileNotFoundError(
            f"Model '{name}' not in GridFS and no fallback path provided."
        )


# ── Listing (powers the Atlas Insights page) ───────────────────────────────
def list_models(name: Optional[str] = None) -> list[dict]:
    fs_files = get_db()[f"{_BUCKET_NAME}.files"]
    q: dict = {}
    if name:
        q["filename"] = name
    out = []
    for doc in fs_files.find(q).sort("uploadDate", -1):
        meta = doc.get("metadata") or {}
        out.append(
            {
                "id": str(doc["_id"]),
                "name": doc.get("filename"),
                "uploaded_at": (doc.get("uploadDate") or datetime.now(timezone.utc)).isoformat(),
                "size_bytes": meta.get("size_bytes", doc.get("length", 0)),
                "sha256": meta.get("sha256"),
                "tags": meta.get("tags", {}),
                "description": meta.get("description"),
            }
        )
    return out


def ensure_default_models() -> dict:
    """One-shot helper: ensure ml_classifier.pkl exists in GridFS.

    Called from the FastAPI startup hook so first run after deploy auto-backfills.
    """
    name = "ml_classifier.pkl"
    fallback = Path(__file__).resolve().parent / name
    try:
        existing = list_models(name=name)
        if existing:
            return {"status": "present", "versions": len(existing)}
        if fallback.exists() and not using_mock():
            oid = upload_model(fallback, name=name, tags={"bootstrap": True})
            return {"status": "uploaded", "id": str(oid)}
        return {"status": "missing", "fallback_exists": fallback.exists()}
    except Exception as e:
        logger.warning("ensure_default_models failed: %s", e)
        return {"status": "error", "error": str(e)}
