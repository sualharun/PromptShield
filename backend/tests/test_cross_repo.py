import json
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from database import Scan, SessionLocal, init_db
from main import app


client = TestClient(app)


def _reset():
    init_db()
    db = SessionLocal()
    try:
        db.query(Scan).delete()
        db.commit()
    finally:
        db.close()


def _add_scan(db, repo, ftype, severity, days_ago=0):
    db.add(
        Scan(
            input_text="test",
            risk_score=75,
            findings_json=json.dumps(
                [
                    {
                        "type": ftype,
                        "severity": severity,
                        "title": "t",
                        "description": "d",
                        "remediation": "r",
                    }
                ]
            ),
            static_count=1,
            ai_count=0,
            total_count=1,
            source="github",
            repo_full_name=repo,
            pr_number=1,
            created_at=datetime.utcnow() - timedelta(days=days_ago),
        )
    )


def test_cross_repo_recurring_findings():
    _reset()
    db = SessionLocal()
    try:
        _add_scan(db, "org/a", "SECRET_IN_PROMPT", "critical", days_ago=1)
        _add_scan(db, "org/b", "SECRET_IN_PROMPT", "high", days_ago=2)
        _add_scan(db, "org/c", "SECRET_IN_PROMPT", "medium", days_ago=3)
        _add_scan(db, "org/a", "ROLE_CONFUSION", "medium", days_ago=1)
        db.commit()
    finally:
        db.close()

    r = client.get("/api/dashboard/cross-repo?min_repos=2")
    assert r.status_code == 200
    data = r.json()
    secret = next(
        (x for x in data["recurring"] if x["finding_type"] == "SECRET_IN_PROMPT"), None
    )
    assert secret is not None
    assert secret["repo_count"] == 3
    # most-severe severity observed wins
    assert secret["severity"] == "critical"
    # ROLE_CONFUSION only appears in one repo → filtered out by min_repos=2
    assert all(x["finding_type"] != "ROLE_CONFUSION" for x in data["recurring"])


def test_cross_repo_trending_respects_window():
    _reset()
    db = SessionLocal()
    try:
        _add_scan(db, "org/a", "SECRET_IN_PROMPT", "high", days_ago=5)
        _add_scan(db, "org/b", "SECRET_IN_PROMPT", "high", days_ago=40)  # outside window
        db.commit()
    finally:
        db.close()

    r = client.get("/api/dashboard/cross-repo?window_days=30&min_repos=1")
    assert r.status_code == 200
    data = r.json()
    # only the 5-days-ago row should be in the top types
    assert "SECRET_IN_PROMPT" in data["top_types_last_30d"]
    # trending series should have 1 datapoint for that type
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
