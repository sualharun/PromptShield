"""MongoDB Change Streams → WebSocket bridge for the live dashboard.

When a new scan lands (especially from the GitHub PR webhook), Atlas pushes a
change-stream event over the oplog. We subscribe via Motor (`watch()`) and
fan it out to every connected dashboard WebSocket client.

Wired into FastAPI as `WS /api/live/scans`.

Important: Change Streams require a replica set. Atlas always provides one,
even on the M0 free tier. They do NOT work on mongomock or against a single
mongod — the WebSocket endpoint will respond with a graceful "live updates
unavailable" message in those environments rather than crashing.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from mongo import C, get_async_db, using_mock

logger = logging.getLogger("promptshield.change_streams")

router = APIRouter(prefix="/api/live", tags=["live"])


def _serialize(event: dict) -> str:
    """Make a change-stream event JSON-safe (ObjectId, datetime, etc.)."""

    def _default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        try:
            from bson import ObjectId

            if isinstance(o, ObjectId):
                return str(o)
        except Exception:
            pass
        return str(o)

    full = event.get("fullDocument") or {}
    out = {
        "operationType": event.get("operationType"),
        "ns": (event.get("ns") or {}).get("coll"),
        "scan": {
            "id": str(full.get("_id")) if full.get("_id") is not None else None,
            "created_at": full.get("created_at"),
            "source": full.get("source"),
            "risk_score": full.get("risk_score"),
            "total_count": (full.get("counts") or {}).get("total", full.get("total_count")),
            "repo_full_name": (full.get("github") or {}).get("repo_full_name"),
            "pr_number": (full.get("github") or {}).get("pr_number"),
            "pr_title": (full.get("github") or {}).get("pr_title"),
            "author_login": (full.get("github") or {}).get("author_login"),
        },
    }
    return json.dumps(out, default=_default)


@router.websocket("/scans")
async def live_scans(ws: WebSocket, source: Optional[str] = None):
    """Pushes one JSON message per new scan inserted into the `scans` collection.

    Client may pass `?source=github` to only get PR scans.
    """
    await ws.accept()

    if using_mock() or get_async_db() is None:
        await ws.send_text(
            json.dumps(
                {
                    "type": "info",
                    "message": "Live updates unavailable — Atlas connection not configured "
                    "(mongomock has no change streams).",
                }
            )
        )
        await ws.close()
        return

    db = get_async_db()
    pipeline: list[dict] = [{"$match": {"operationType": "insert"}}]
    if source:
        pipeline.append({"$match": {"fullDocument.source": source}})

    await ws.send_text(json.dumps({"type": "ready", "collection": C.SCANS}))

    try:
        async with db[C.SCANS].watch(pipeline, full_document="updateLookup") as stream:
            async for change in stream:
                try:
                    await ws.send_text(_serialize(change))
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    logger.warning("Failed to send change event: %s", e)
                    break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Change stream terminated: %s", e)
        try:
            await ws.send_text(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
