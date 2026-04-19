"""Cross-repo dashboard tests — Mongo-backed (v0.4)."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from main import app
from mongo import C, col


client = TestClient(app)


def _reset():
    col(C.SCANS).delete_many({})


def _add_scan(repo: str, ftype: str, severity: str, days_ago: int = 0) -> None:
    col(C.SCANS).insert_one(
        {
            "input_text": "test",
            "risk_score": 75.0,
            "findings": [
                {
                    "type": ftype,
                    "severity": severity,
                    "title": "t",
                    "description": "d",
                    "remediation": "r",
                }
            ],
            "counts": {"static": 1, "ai": 0, "total": 1},
            "source": "github",
            "github": {
                "repo_full_name": repo,
                "pr_number": 1,
                "pr_title": None,
                "pr_url": None,
                "commit_sha": None,
                "author_login": None,
            },
            "llm_targets": [],
            "created_at": datetime.now(timezone.utc) - timedelta(days=days_ago),
        }
    )


def test_cross_repo_recurring_findings():
    _reset()
    _add_scan("org/a", "SECRET_IN_PROMPT", "critical", days_ago=1)
    _add_scan("org/b", "SECRET_IN_PROMPT", "high", days_ago=2)
    _add_scan("org/c", "SECRET_IN_PROMPT", "medium", days_ago=3)
    _add_scan("org/a", "ROLE_CONFUSION", "medium", days_ago=1)

    r = client.get("/api/dashboard/cross-repo?min_repos=2")
    assert r.status_code == 200
    data = r.json()
    secret = next(
        (x for x in data["recurring"] if x["finding_type"] == "SECRET_IN_PROMPT"), None
    )
    assert secret is not None
    assert secret["repo_count"] == 3
    assert secret["severity"] == "critical"
    assert all(x["finding_type"] != "ROLE_CONFUSION" for x in data["recurring"])


def test_cross_repo_trending_respects_window():
    _reset()
    _add_scan("org/a", "SECRET_IN_PROMPT", "high", days_ago=5)
    _add_scan("org/b", "SECRET_IN_PROMPT", "high", days_ago=40)

    r = client.get("/api/dashboard/cross-repo?window_days=30&min_repos=1")
    assert r.status_code == 200
    data = r.json()
    assert "SECRET_IN_PROMPT" in data["top_types_last_30d"]
    pts = [p for p in data["trending"] if p["finding_type"] == "SECRET_IN_PROMPT"]
    assert len(pts) == 1


def test_cross_repo_empty_when_no_scans():
    _reset()
    r = client.get("/api/dashboard/cross-repo")
    assert r.status_code == 200
    data = r.json()
    assert data["recurring"] == []
    assert data["trending"] == []
    assert data["top_types_last_30d"] == []
