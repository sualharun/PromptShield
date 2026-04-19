"""Tests for operations endpoints and command center — Mongo-backed (v0.4)."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _setup():
    from mongo import C, col
    col(C.SCANS).delete_many({})


def test_metrics_endpoint():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "counters" in data
    assert "histograms" in data
    assert "gauges" in data


def test_traces_endpoint():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/traces")
    assert r.status_code == 200
    assert "spans" in r.json()


def test_slos_endpoint():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/slos")
    assert r.status_code == 200
    data = r.json()
    assert "slos" in data
    assert "total_requests" in data


def test_queue_status():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/jobs/queue")
    assert r.status_code == 200
    data = r.json()
    assert "pending" in data
    assert "completed" in data


def test_command_center_empty():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/command-center")
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert "anomalies" in data
    assert "ownership_routing" in data
    assert "sla_breaches" in data
    assert data["total_scans"] == 0


def test_command_center_with_scan_data():
    from main import app
    from mongo import C, col

    now = datetime.now(timezone.utc)
    col(C.SCANS).insert_one(
        {
            "input_text": "test",
            "risk_score": 80.0,
            "findings": [
                {"type": "SECRETS", "severity": "critical", "title": "Key"},
                {"type": "INJECTION", "severity": "high", "title": "Prompt"},
            ],
            "counts": {"static": 2, "ai": 0, "total": 2},
            "source": "github",
            "github": {
                "repo_full_name": "org/repo",
                "pr_number": 42,
                "author_login": "testuser",
                "pr_title": None,
                "pr_url": None,
                "commit_sha": None,
            },
            "llm_targets": [],
            "created_at": now,
        }
    )

    client = TestClient(app)
    r = client.get("/api/ops/command-center")
    assert r.status_code == 200
    data = r.json()
    assert data["total_scans"] == 1
    assert data["gate_failures"] == 1
    assert len(data["events"]) == 1
    event = data["events"][0]
    assert event["gate_result"] == "fail"
    assert event["severity_counts"]["critical"] == 1


def test_dead_letter_endpoint():
    from main import app
    client = TestClient(app)
    r = client.get("/api/ops/jobs/dead-letter/list")
    assert r.status_code == 200
    assert "dead_letter" in r.json()
