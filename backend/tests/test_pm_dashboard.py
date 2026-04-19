from datetime import datetime, timedelta

from fastapi.testclient import TestClient

import main
import repositories as repos
from auth import hash_password
from mongo import C, col


client = TestClient(main.app)


def _reset():
    col(C.USERS).delete_many({})
    col(C.SCANS).delete_many({})


def _seed_user(email: str, role: str = "pm") -> None:
    repos.insert_user(
        {
            "email": email,
            "name": "Test",
            "password_hash": hash_password("pw"),
            "role": role,
        }
    )


def _scan_doc(*, created_at, risk_score, repo, pr_number, commit_sha, author):
    return {
        "created_at": created_at,
        "input_text": "x",
        "risk_score": float(risk_score),
        "findings": [],
        "counts": {"static": 0, "ai": 0, "total": 0},
        "source": "github",
        "github": {
            "repo_full_name": repo,
            "pr_number": pr_number,
            "pr_title": None,
            "pr_url": None,
            "commit_sha": commit_sha,
            "author_login": author,
        },
        "llm_targets": [],
    }


def _seed_scans():
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    docs = [
        # alice: one passing, one failing
        _scan_doc(created_at=t0, risk_score=30, repo="ibm/promptshield", pr_number=1, commit_sha="aaa", author="alice"),
        # bob: failing then passing on same PR -> remediation delta populated
        _scan_doc(created_at=t0 + timedelta(minutes=5), risk_score=85, repo="ibm/promptshield", pr_number=2, commit_sha="bbb", author="bob"),
        _scan_doc(created_at=t0 + timedelta(minutes=65), risk_score=40, repo="ibm/promptshield", pr_number=2, commit_sha="bbb2", author="bob"),
        # carol: failing, never remediated
        _scan_doc(created_at=t0 + timedelta(minutes=30), risk_score=90, repo="ibm/other", pr_number=7, commit_sha="ccc", author="carol"),
    ]
    col(C.SCANS).insert_many(docs)


def _login(email: str):
    r = client.post(
        "/api/auth/login", json={"email": email, "password": "pw"}
    )
    assert r.status_code == 200


def test_pm_dashboard_requires_auth():
    _reset()
    client.cookies.clear()
    r = client.get("/api/dashboard/pm")
    assert r.status_code == 401


def test_pm_dashboard_rejects_viewer():
    _reset()
    _seed_user("viewer@x.com", role="viewer")
    _login("viewer@x.com")
    r = client.get("/api/dashboard/pm")
    assert r.status_code == 403
    client.cookies.clear()


def test_pm_dashboard_aggregates_authors_and_remediation():
    _reset()
    _seed_scans()
    _seed_user("pm@x.com", role="pm")
    _login("pm@x.com")

    r = client.get("/api/dashboard/pm")
    assert r.status_code == 200
    body = r.json()

    authors = {a["author_login"]: a for a in body["by_author"]}
    assert set(authors) == {"alice", "bob", "carol"}
    assert authors["bob"]["scan_count"] == 2
    assert authors["bob"]["gate_failures"] == 1  # only the 85 crossed the gate
    assert authors["carol"]["gate_failures"] == 1
    assert authors["alice"]["gate_failures"] == 0

    blocked = body["blocked_prs"]
    assert {b["author_login"] for b in blocked} == {"bob", "carol"}

    deltas = {(d["repo_full_name"], d["pr_number"]): d for d in body["remediation_deltas"]}
    bob = deltas[("ibm/promptshield", 2)]
    assert bob["delta_seconds"] == 60 * 60  # 65 - 5 = 60 minutes
    assert bob["first_passing_at"] is not None
    carol = deltas[("ibm/other", 7)]
    assert carol["delta_seconds"] is None
    assert carol["first_passing_at"] is None

    repos = {r["repo_full_name"] for r in body["repo_health"]}
    assert repos == {"ibm/promptshield", "ibm/other"}

    client.cookies.clear()
