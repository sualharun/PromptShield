from fastapi.testclient import TestClient

from main import app
from mongo import C, col
from suppression import annotate, finding_signature, suppressed_signatures


client = TestClient(app)


def _reset():
    col(C.FINDING_SUPPRESSIONS).delete_many({})


def test_signature_is_stable_and_short():
    f = {"type": "SECRET_LEAK", "title": "OpenAI key", "evidence": "sk-abcdef1234"}
    sig = finding_signature(f)
    assert sig == finding_signature(dict(f))
    assert len(sig) == 16


def test_signature_differs_when_type_changes():
    a = finding_signature({"type": "SECRET_LEAK", "title": "X", "evidence": ""})
    b = finding_signature({"type": "ROLE_CONFUSION", "title": "X", "evidence": ""})
    assert a != b


def test_annotate_flags_suppressed():
    findings = [
        {"type": "SECRET_LEAK", "title": "key", "evidence": "sk-xxx"},
        {"type": "ROLE_CONFUSION", "title": "role", "evidence": ""},
    ]
    sigs = {finding_signature(findings[0])}
    out = annotate(findings, sigs)
    assert out[0]["suppressed"] is True
    assert out[1]["suppressed"] is False
    assert all("signature" in f for f in out)


def test_suppressed_signatures_scoping():
    _reset()
    from datetime import datetime, timezone
    col(C.FINDING_SUPPRESSIONS).insert_many(
        [
            {
                "signature": "globalsig",
                "finding_type": "T",
                "finding_title": "t",
                "repo_full_name": None,
                "suppressed_by": "tester",
                "created_at": datetime.now(timezone.utc),
            },
            {
                "signature": "reposig",
                "finding_type": "T",
                "finding_title": "t",
                "repo_full_name": "org/repo-a",
                "suppressed_by": "tester",
                "created_at": datetime.now(timezone.utc),
            },
        ]
    )
    assert suppressed_signatures(None, "org/repo-a") == {"globalsig", "reposig"}
    assert suppressed_signatures(None, "org/other") == {"globalsig"}
    assert suppressed_signatures(None, None) == {"globalsig"}


def test_api_create_list_delete_round_trip():
    _reset()
    finding = {"type": "SECRET_LEAK", "title": "key", "evidence": "sk-abc"}
    r = client.post(
        "/api/suppressions",
        json={"finding": finding, "repo_full_name": "org/repo-a", "reason": "demo"},
    )
    assert r.status_code == 200
    row = r.json()
    assert row["signature"] == finding_signature(finding)
    assert row["repo_full_name"] == "org/repo-a"

    # idempotent on same (sig, repo)
    r2 = client.post(
        "/api/suppressions",
        json={"finding": finding, "repo_full_name": "org/repo-a"},
    )
    assert r2.status_code == 200
    assert r2.json()["id"] == row["id"]

    listed = client.get("/api/suppressions").json()
    assert any(it["id"] == row["id"] for it in listed)

    d = client.delete(f"/api/suppressions/{row['id']}")
    assert d.status_code == 200
    assert d.json() == {"ok": True}
    listed = client.get("/api/suppressions").json()
    assert all(it["id"] != row["id"] for it in listed)


def test_scan_report_includes_suppressed_flag():
    _reset()
    client.post("/api/scan", json={"text": "api_key = 'sk-test-1234567890abcd'"})
    scans = client.get("/api/scans").json()
    assert scans
    latest_id = scans[0]["id"]
    first = client.get(f"/api/scans/{latest_id}").json()
    assert first["findings"], "expected at least one finding"
    target = first["findings"][0]
    assert target.get("suppressed") is False
    assert target.get("signature")

    sup = client.post(
        "/api/suppressions",
        json={"finding": target, "repo_full_name": None},
    )
    assert sup.status_code == 200

    after = client.get(f"/api/scans/{latest_id}").json()
    matching = [f for f in after["findings"] if f.get("signature") == target["signature"]]
    assert matching and matching[0]["suppressed"] is True
