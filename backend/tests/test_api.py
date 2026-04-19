from fastapi.testclient import TestClient

import main


client = TestClient(main.app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.headers.get("x-request-id")


def test_scan_rejects_empty():
    r = client.post("/api/scan", json={"text": "   "})
    assert r.status_code == 400


def test_scan_runs_and_persists(monkeypatch):
    # Force AI layer off so the test is deterministic.
    monkeypatch.setattr("scan_pipeline.ai_scan", lambda text: [])
    r = client.post(
        "/api/scan",
        json={"text": 'prompt = f"do this: {user_input}"\nkey = "sk-proj-AbCdEfGhIjKlMnOpQrStUv12"'},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] > 0
    assert body["total_count"] >= 2
    assert any(f["type"] == "DIRECT_INJECTION" for f in body["findings"])

    # The persisted input should be redacted (no raw secret round-tripped).
    assert "sk-proj-AbCdEfGh" not in body["input_text"]

    # History endpoint surfaces the new scan.
    listing = client.get("/api/scans").json()
    assert any(s["id"] == body["id"] for s in listing)

    # Get-by-id returns the same report.
    detail = client.get(f"/api/scans/{body['id']}").json()
    assert detail["id"] == body["id"]


def test_rate_limiter(monkeypatch):
    from rate_limit import SlidingWindowLimiter

    monkeypatch.setattr(main, "scan_limiter", SlidingWindowLimiter(2, 60))
    monkeypatch.setattr("scan_pipeline.ai_scan", lambda text: [])
    payload = {"text": "hello world this is fine"}
    assert client.post("/api/scan", json=payload).status_code == 200
    assert client.post("/api/scan", json=payload).status_code == 200
    third = client.post("/api/scan", json=payload)
    assert third.status_code == 429
    assert "Retry-After" in third.headers
