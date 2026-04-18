"""In-process async job queue with retry and dead-letter handling.

Design: uses asyncio + ThreadPoolExecutor for CPU-bound scan work.
No Redis dependency — suitable for single-node hackathon deployment.
Upgrade path: swap InMemoryQueue for Arq/Celery backend via the same interface.
"""

import asyncio
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from models import ScanJob
from database import SessionLocal

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
        org_id: Optional[int] = None,
        created_by: Optional[int] = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        db = SessionLocal()
        try:
            job = ScanJob(
                id=job_id,
                org_id=org_id,
                job_type=job_type,
                input_text=payload.get("text", ""),
                status="pending",
                created_by=created_by,
            )
            db.add(job)
            db.commit()
        finally:
            db.close()

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
                    self._update_retry(job_id, attempt + 1)

        self._mark_failed(job_id, "Max retries exceeded")
        self._dead_letter.append({
            "job_id": job_id,
            "job_type": job_type,
            "failed_at": datetime.now(timezone.utc).isoformat(),
        })

    def _update_status(self, job_id: str, status: str):
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = status
                if status == "running":
                    job.started_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def _update_retry(self, job_id: str, count: int):
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.retry_count = count
                db.commit()
        finally:
            db.close()

    def _mark_completed(self, job_id: str, result: Any):
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = "completed"
                job.completed_at = datetime.now(timezone.utc)
                if isinstance(result, dict) and "scan_id" in result:
                    job.result_scan_id = result["scan_id"]
                db.commit()
        finally:
            db.close()
        self._running.pop(job_id, None)

    def _mark_failed(self, job_id: str, error: str):
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = "dead_letter"
                job.error_message = error
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        self._running.pop(job_id, None)

    def get_status(self, job_id: str) -> Optional[Dict]:
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if not job:
                return None
            return {
                "id": job.id,
                "status": job.status,
                "job_type": job.job_type,
                "retry_count": job.retry_count,
                "result_scan_id": job.result_scan_id,
                "error_message": job.error_message,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }
        finally:
            db.close()

    def list_dead_letters(self) -> list[Dict]:
        return list(self._dead_letter)

    def queue_depth(self) -> Dict:
        db = SessionLocal()
        try:
            pending = db.query(ScanJob).filter(ScanJob.status == "pending").count()
            running = db.query(ScanJob).filter(ScanJob.status == "running").count()
            completed = db.query(ScanJob).filter(ScanJob.status == "completed").count()
            failed = db.query(ScanJob).filter(ScanJob.status == "dead_letter").count()
            return {
                "pending": pending,
                "running": running,
                "completed": completed,
                "dead_letter": failed,
            }
        finally:
            db.close()


job_queue = JobQueue()
