"""Tests for the async job queue — run via asyncio.run()."""

import os
import asyncio

os.environ.setdefault("DATABASE_URL", "sqlite:///")

import pytest
from database import Base, engine, SessionLocal, safe_create_all
from models import ScanJob


@pytest.fixture(autouse=True)
def _setup():
    Base.metadata.drop_all(bind=engine)
    safe_create_all()


def _fresh_queue():
    from job_queue import JobQueue
    return JobQueue(max_workers=2)


def test_enqueue_and_complete():
    async def _run():
        q = _fresh_queue()
        q.register("scan", lambda payload: {"scan_id": 42})
        job_id = await q.enqueue("scan", {"text": "hello"})
        assert len(job_id) == 12
        await asyncio.sleep(0.5)
        status = q.get_status(job_id)
        assert status is not None
        assert status["status"] == "completed"
        assert status["result_scan_id"] == 42

    asyncio.run(_run())


def test_unregistered_handler_marks_failed():
    async def _run():
        q = _fresh_queue()
        job_id = await q.enqueue("unknown_type", {"text": "test"})
        await asyncio.sleep(0.3)
        status = q.get_status(job_id)
        assert status["status"] == "dead_letter"
        assert "No handler" in status["error_message"]

    asyncio.run(_run())


def test_queue_depth():
    async def _run():
        q = _fresh_queue()
        q.register("scan", lambda p: {"scan_id": 1})
        await q.enqueue("scan", {"text": "a"})
        await asyncio.sleep(0.5)
        depth = q.queue_depth()
        assert "pending" in depth
        assert "completed" in depth
        assert depth["completed"] >= 1

    asyncio.run(_run())


def test_dead_letter_list():
    async def _run():
        def always_fails(payload):
            raise RuntimeError("permanent failure")

        q = _fresh_queue()
        q.register("scan", always_fails)
        job_id = await q.enqueue("scan", {"text": "fail"})
        await asyncio.sleep(12)
        assert len(q.list_dead_letters()) >= 1
        status = q.get_status(job_id)
        assert status["status"] == "dead_letter"

    asyncio.run(_run())
