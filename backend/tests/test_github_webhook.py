import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import github_webhook
import main


SECRET = "test-secret-please-ignore"


def _sign(body: bytes) -> str:
    mac = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _pr_payload():
    return {
        "action": "opened",
        "installation": {"id": 999},
        "repository": {
            "name": "demo",
            "full_name": "octo/demo",
            "owner": {"login": "octo"},
        },
        "pull_request": {
            "number": 42,
            "title": "Add risky prompt",
            "html_url": "https://github.com/octo/demo/pull/42",
            "head": {"sha": "deadbeefcafebabe1234567890abcdef12345678"},
        },
    }


class FakeGitHubClient:
    """Records calls and returns canned responses."""

    captured: dict = {}

    def __init__(self, *args, **kwargs):
        FakeGitHubClient.captured = {
            "checks": [],
            "check_updates": [],
            "reviews": [],
        }

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def list_pr_files(self, owner, repo, number):
        return [
            {
                "filename": "prompts/build.py",
                "changes": 4,
                "patch": (
                    "@@ -1,3 +1,4 @@\n"
                    " def build(user_input):\n"
                    "-    return 'plain'\n"
                    "+    secret = \"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234\"\n"
                    "+    return f\"do this: {user_input}\"\n"
                ),
            },
            {
                "filename": "img/logo.png",
                "changes": 1,
                "patch": "binary",
            },
        ]

    def get_file_content(self, owner, repo, path, ref):
        # Patch above adds at new-side lines 2 and 3, so the file content must
        # have the vulnerable lines at those exact positions.
        return (
            "def build(user_input):\n"
            "    secret = \"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234\"\n"
            "    return f\"do this: {user_input}\"\n"
        )

    def create_review(self, owner, repo, number, commit_id, body, comments, event="COMMENT"):
        FakeGitHubClient.captured["reviews"].append(
            {"comments": comments, "body": body, "commit_id": commit_id}
        )
        return {"id": 1}

    def create_check_run(self, owner, repo, payload):
        FakeGitHubClient.captured["checks"].append(payload)
        return {"id": 12345}

    def update_check_run(self, owner, repo, check_run_id, payload):
        FakeGitHubClient.captured["check_updates"].append(payload)
        return {"id": check_run_id}


def _setup(monkeypatch):
    import scan_pipeline

    monkeypatch.setattr(main.settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setattr(github_webhook.settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setattr(github_webhook.settings, "RISK_GATE_THRESHOLD", 50)
    monkeypatch.setattr(scan_pipeline, "ai_scan", lambda text: [])
    monkeypatch.setattr(github_webhook, "get_installation_token", lambda iid: "tok")
    monkeypatch.setattr(github_webhook, "_make_client", lambda token: FakeGitHubClient())
    return TestClient(main.app)


def test_rejects_bad_signature(monkeypatch):
    client = _setup(monkeypatch)
    body = json.dumps(_pr_payload()).encode()
    r = client.post(
        "/api/github/webhook?wait=true",
        content=body,
        headers={
            "x-hub-signature-256": "sha256=deadbeef",
            "x-github-event": "pull_request",
            "x-github-delivery": "test-1",
            "content-type": "application/json",
        },
    )
    assert r.status_code == 401


def test_ping_event_succeeds_with_valid_signature(monkeypatch):
    client = _setup(monkeypatch)
    body = b"{}"
    r = client.post(
        "/api/github/webhook?wait=true",
        content=body,
        headers={
            "x-hub-signature-256": _sign(body),
            "x-github-event": "ping",
            "x-github-delivery": "test-2",
            "content-type": "application/json",
        },
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_pull_request_runs_full_pipeline(monkeypatch):
    client = _setup(monkeypatch)
    body = json.dumps(_pr_payload()).encode()
    r = client.post(
        "/api/github/webhook?wait=true",
        content=body,
        headers={
            "x-hub-signature-256": _sign(body),
            "x-github-event": "pull_request",
            "x-github-delivery": "test-3",
            "content-type": "application/json",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["risk_score"] > 0
    assert body["scan_id"] is not None

    captured = FakeGitHubClient.captured
    # one in-progress check, one completed check
    assert len(captured["checks"]) == 1
    assert captured["checks"][0]["status"] == "in_progress"
    assert len(captured["check_updates"]) == 1
    update = captured["check_updates"][0]
    assert update["status"] == "completed"
    # threshold was set to 50; the secret + injection findings push us over
    assert update["conclusion"] == "failure"

    # one review with at least one comment, all anchored to changed lines (3 or 4)
    assert len(captured["reviews"]) == 1
    comments = captured["reviews"][0]["comments"]
    assert len(comments) >= 1
    for c in comments:
        assert c["path"] == "prompts/build.py"
        assert c["side"] == "RIGHT"
        assert c["line"] in {2, 3}

    # scan persisted with source=github
    listing = client.get("/api/scans?source=github").json()
    assert any(
        s["repo_full_name"] == "octo/demo" and s["pr_number"] == 42 for s in listing
    )

    # dashboard endpoint reflects the new scan
    dash = client.get("/api/dashboard/github").json()
    assert dash["total_pr_scans"] >= 1
    assert dash["repos_covered"] >= 1
    assert any(r["repo_full_name"] == "octo/demo" for r in dash["by_repo"])


def test_unhandled_action_is_ignored(monkeypatch):
    client = _setup(monkeypatch)
    payload = _pr_payload()
    payload["action"] = "labeled"
    body = json.dumps(payload).encode()
    r = client.post(
        "/api/github/webhook",
        content=body,
        headers={
            "x-hub-signature-256": _sign(body),
            "x-github-event": "pull_request",
            "x-github-delivery": "test-4",
            "content-type": "application/json",
        },
    )
    assert r.status_code == 200
    assert r.json().get("ignored_action") == "labeled"


def test_anchor_missing_line_numbers_uses_added_lines():
    findings = [
        {
            "type": "INSECURE_FILE_UPLOAD",
            "title": "Insecure file upload handler without validation controls",
            "description": "write bytes from upload directly to disk",
            "evidence": "dest.write_bytes(raw)",
            "line_number": None,
        }
    ]
    content = (
        "async def insecure_upload(file):\n"
        "    raw = await file.read()\n"
        "    dest.write_bytes(raw)\n"
    )
    added = {3}
    github_webhook._anchor_missing_line_numbers(findings, content, added)
    assert findings[0]["line_number"] == 3


def test_top_attack_paths_markdown_contains_expected_fields():
    md = github_webhook._top_attack_paths_markdown(
        [
            {
                "type": "INSECURE_FILE_UPLOAD",
                "severity": "critical",
                "confidence": 0.9,
                "path": "backend/taskboard/vuln_arbitrary_upload.py",
                "line_number": 22,
                "remediation": "Add MIME, extension, size, and safe-path checks.",
                "owner_team": "@security-platform",
            }
        ]
    )
    assert "Top Attack Paths" in md
    assert "backend/taskboard/vuln_arbitrary_upload.py:22" in md
    assert "owner/team: `@security-platform`" in md
    assert "Expected risk reduction: **-40**" in md
