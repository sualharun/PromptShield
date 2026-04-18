"""In-process async job queue with retry and dead-letter handling.

v0.4: Mongo-backed (`scan_jobs` collection). Same external interface as the
SQL version — handlers and the `enqueue / get_status / queue_depth` callers
don't need to change.

Design: asyncio + ThreadPoolExecutor for CPU-bound scan work. No Redis
dependency — suitable for single-node hackathon deployment. Upgrade path:
swap InMemoryQueue for Arq/Celery via the same interface.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

import repositories as repos
from mongo import C, col


logger = logging.getLogger("promptshield.jobs")

MAX_WORKERS = 4
MAX_RETRIES = 3


class JobQueue:
    def __init__(self, max_workers: int = MAX_WORKERS):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._handlers: Dict[str, Callable] = {}
        self._running: Dict[str, asyncio.Task] = {}
        self._dead_letter: list[Dict[str, Any]] = []

    def register(self, job_type: str, handler: Callable):
        self._handlers[job_type] = handler

    async def enqueue(
        self,
        job_type: str,
        payload: Dict[str, Any],
        org_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        repos.insert_scan_job(
            {
                "id": job_id,
                "org_id": str(org_id) if org_id is not None else None,
                "job_type": job_type,
                "input_text": payload.get("text", ""),
                "status": "pending",
                "created_by": str(created_by) if created_by is not None else None,
                "retry_count": 0,
            }
        )

        task = asyncio.create_task(self._run(job_id, job_type, payload))
        self._running[job_id] = task
        return job_id

    async def _run(self, job_id: str, job_type: str, payload: Dict[str, Any]):
        handler = self._handlers.get(job_type)
        if not handler:
            self._mark_failed(job_id, f"No handler for job type: {job_type}")
            return

        self._update_status(job_id, "running")
        loop = asyncio.get_event_loop()

        for attempt in range(MAX_RETRIES):
            try:
                result = await loop.run_in_executor(
                    self._executor, handler, payload
                )
                self._mark_completed(job_id, result)
                return
            except Exception as e:
                logger.warning(
                    "job attempt failed",
                    extra={
                        "job_id": job_id,
                        "attempt": attempt + 1,
                        "error": str(e),
                    },
                )
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(min(2 ** attempt, 8))
                    repos.update_scan_job(job_id, {"retry_count": attempt + 1})

        self._mark_failed(job_id, "Max retries exceeded")
        self._dead_letter.append(
            {
                "job_id": job_id,
                "job_type": job_type,
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def _update_status(self, job_id: str, status: str):
        fields: dict = {"status": status}
        if status == "running":
            fields["started_at"] = datetime.now(timezone.utc)
        repos.update_scan_job(job_id, fields)

    def _mark_completed(self, job_id: str, result: Any):
        fields: dict = {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc),
        }
        if isinstance(result, dict) and "scan_id" in result:
            fields["result_scan_id"] = str(result["scan_id"])
        repos.update_scan_job(job_id, fields)
        self._running.pop(job_id, None)

    def _mark_failed(self, job_id: str, error: str):
        repos.update_scan_job(
            job_id,
            {
                "status": "dead_letter",
                "error_message": error,
                "completed_at": datetime.now(timezone.utc),
            },
        )
        self._running.pop(job_id, None)

    def get_status(self, job_id: str) -> Optional[Dict]:
        job = repos.get_scan_job(job_id)
        if not job:
            return None
        return {
            "id": job.get("id") or str(job.get("_id")),
            "status": job.get("status"),
            "job_type": job.get("job_type"),
            "retry_count": int(job.get("retry_count") or 0),
            "result_scan_id": job.get("result_scan_id"),
            "error_message": job.get("error_message"),
            "created_at": job.get("created_at").isoformat() if job.get("created_at") else None,
            "started_at": job.get("started_at").isoformat() if job.get("started_at") else None,
            "completed_at": job.get("completed_at").isoformat() if job.get("completed_at") else None,
        }

    def list_dead_letters(self) -> list[Dict]:
        return list(self._dead_letter)

    def queue_depth(self) -> Dict:
        c = col(C.SCAN_JOBS)
        return {
            "pending": c.count_documents({"status": "pending"}),
            "running": c.count_documents({"status": "running"}),
            "completed": c.count_documents({"status": "completed"}),
            "dead_letter": c.count_documents({"status": "dead_letter"}),
        }


job_queue = JobQueue()
