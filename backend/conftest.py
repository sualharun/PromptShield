import os
import sys

# Make backend/ importable regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(__file__))

os.environ.setdefault("REDACT_PERSISTED_INPUT", "true")
os.environ.setdefault("SCAN_RATE_LIMIT", "1000")  # don't trip during tests

# ── MongoDB: use mongomock in tests (no MONGODB_URI -> automatic fallback) ─
# Atlas-only features ($vectorSearch, $search, $rankFusion, change streams)
# automatically degrade to in-process equivalents in mongomock so the unit
# test suite stays runnable without a network call. Integration tests that
# require a real Atlas cluster should set MONGODB_URI explicitly.
# Force-empty (not pop) so config.py's load_dotenv(override=False) doesn't
# re-populate MONGODB_URI from a developer's .env file.
os.environ["MONGODB_URI"] = ""
os.environ["MONGODB_DB"] = "promptshield_test"
os.environ.setdefault("PRIMARY_STORE", "mongo")
os.environ.setdefault("EMBEDDING_PROVIDER", "local")

from mongo import init_collections as _init_mongo_collections  # noqa: E402

try:
    _init_mongo_collections()
except Exception:
    # mongomock will silently skip Atlas-only features; soft-fail rather
    # than blow up the whole suite if a collection cannot be created.
    pass

import pytest  # noqa: E402


@pytest.fixture
def mock_ai_scan(monkeypatch):
    """Stub the Gemini AI layer with a deterministic agentic finding list.

    Use this in any test that exercises /api/scan or _process_pr end-to-end
    so we don't hit Vertex AI from CI (slow, costs money, requires ADC).

    The stubbed payload always includes one DANGEROUS_TOOL_CAPABILITY and
    one LLM_OUTPUT_TO_EXEC finding so tests can assert that AI findings
    flow through the pipeline and into the score breakdown.
    """

    def _fake_ai_scan(text):
        return [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "title": "Tool exposes shell to LLM with no validation",
                "description": "AI fixture finding (deterministic for tests).",
                "line_number": 1,
                "remediation": "Wrap in allowlist + add input validation.",
                "source": "ai",
                "confidence": 0.92,
                "evidence": "subprocess.run(cmd, shell=True)",
                "cwe": "CWE-78",
                "owasp": "LLM06: Excessive Agency",
            },
            {
                "type": "LLM_OUTPUT_TO_EXEC",
                "severity": "critical",
                "title": "LLM response passed directly to eval()",
                "description": "AI fixture finding (deterministic for tests).",
                "line_number": 1,
                "remediation": "Never eval LLM output; parse & validate first.",
                "source": "ai",
                "confidence": 0.95,
                "evidence": "eval(response.text)",
                "cwe": "CWE-95",
                "owasp": "LLM05: Improper Output Handling",
            },
        ]

    # Patch every import path the function is reachable through.
    monkeypatch.setattr("ai_analyzer.ai_scan", _fake_ai_scan)
    try:
        import main as _main

        monkeypatch.setattr(_main, "ai_scan", _fake_ai_scan)
    except Exception:
        pass
    try:
        import github_webhook as _gh

        monkeypatch.setattr(_gh, "ai_scan", _fake_ai_scan)
    except Exception:
        pass
    return _fake_ai_scan


@pytest.fixture
def client():
    """Shared FastAPI TestClient. Lazy-imports `main` so tests that don't
    need the full app (and the heavyweight imports it pulls in) don't pay
    the cost or fail on optional deps like sklearn."""
    from fastapi.testclient import TestClient
    import main as _main

    return TestClient(_main.app)
