"""Phase-8 integration tests — exercises the full agentic-security Atlas
stack against mongomock so the suite stays runnable without a live cluster.

Coverage map:
  • Tool registry: derive → upsert → idempotent re-run → aggregations.
  • Exploit corpus: seed → similarity search → API contract.
  • Alert fan-out: critical findings escalate, medium-sev don't, dedupe by
    signature, ack moves a row to acknowledged=True.
  • Timeline: snapshot only when agentic content exists; window returns a
    rolling avg even on the mongomock fallback.
  • Hybrid search over agent_tools: regex side fires deterministically and
    fusion_score is attached to each result.
  • End-to-end: POST /api/scan with a vulnerable agent payload populates
    agent_tools + agent_alerts + agent_surface_timeline.

Each test is isolated by clearing the relevant collections at the top of
the test, so order doesn't matter.
"""
from __future__ import annotations

from mongo import C, col


# ── Module-level reset helpers ─────────────────────────────────────────────
def _reset_agent_collections():
    for name in (
        C.AGENT_TOOLS,
        C.AGENT_EXPLOIT_CORPUS,
        C.AGENT_ALERTS,
        C.AGENT_SURFACE_TIMELINE,
    ):
        col(name).delete_many({})


# ── 8A: Agent Tool Registry ────────────────────────────────────────────────
def test_registry_derives_and_persists_tool_records():
    _reset_agent_collections()
    from agent_registry import (
        persist_tools_from_findings,
        list_agent_tools,
        capability_aggregates,
    )

    findings = [
        {
            "type": "DANGEROUS_TOOL_CAPABILITY",
            "severity": "critical",
            "title": "Tool 'run_shell' exposes subprocess to LLM",
            "evidence": "@tool\ndef run_shell(cmd):",
            "line_number": 12,
        },
        {
            "type": "TOOL_EXCESSIVE_SCOPE",
            "severity": "high",
            "title": "Tool 'delete_file' accepts arbitrary path",
            "evidence": "@tool\ndef delete_file(path):",
            "line_number": 22,
        },
    ]
    out = persist_tools_from_findings(
        findings, repo_full_name="acme/agent", scan_id="s1"
    )
    names = sorted(r["tool_name"] for r in out)
    assert names == ["delete_file", "run_shell"]

    # Both detected as LangChain (the @tool decorator).
    by_name = {r["tool_name"]: r for r in list_agent_tools()}
    assert by_name["run_shell"]["framework"] == "langchain"
    assert by_name["run_shell"]["risk_level"] == "critical"
    assert by_name["delete_file"]["risk_level"] == "high"

    # Capability aggregations expose the surface.
    caps = {c["capability"]: c for c in capability_aggregates()}
    assert "dangerous-body" in caps
    assert "unbounded-scope" in caps


def test_registry_upsert_is_idempotent_per_repo_and_tool():
    _reset_agent_collections()
    from agent_registry import persist_tools_from_findings, list_agent_tools

    findings = [
        {
            "type": "DANGEROUS_TOOL_CAPABILITY",
            "severity": "critical",
            "title": "Tool 'run_shell' exposes subprocess to LLM",
            "evidence": "@tool\ndef run_shell(cmd):",
            "line_number": 12,
        }
    ]
    persist_tools_from_findings(findings, repo_full_name="acme/agent", scan_id="s1")
    persist_tools_from_findings(findings, repo_full_name="acme/agent", scan_id="s2")

    rows = list_agent_tools(repo_full_name="acme/agent")
    assert len(rows) == 1, "re-running the same scan must not duplicate the tool row"
    assert int(rows[0].get("occurrences") or 0) >= 2


def test_registry_writes_embedding_for_hybrid_search():
    _reset_agent_collections()
    from agent_registry import persist_tools_from_findings

    persist_tools_from_findings(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "title": "Tool 'run_shell'",
                "evidence": "@tool\ndef run_shell(cmd): subprocess.run(cmd)",
                "line_number": 1,
            }
        ],
        repo_full_name="acme/agent",
        scan_id="s1",
    )
    doc = col(C.AGENT_TOOLS).find_one({"tool_name": "run_shell"})
    # Embedding may be None in environments where neither voyage nor
    # sentence-transformers nor the hash fallback fired, but
    # `embedding_text` must always be present.
    assert doc is not None
    assert doc.get("embedding_text"), "embedding_text must be set for downstream search"


# ── 8B: Exploit corpus + vector similarity ─────────────────────────────────
def test_exploit_corpus_seed_is_idempotent():
    _reset_agent_collections()
    from agent_vector import seed_exploit_corpus

    out1 = seed_exploit_corpus()
    assert out1["total"] >= 10
    out2 = seed_exploit_corpus()
    # Re-run should not insert anything new.
    assert out2["inserted"] == 0
    assert out2["total"] == out1["total"]


def test_exploit_similarity_returns_ranked_hits():
    _reset_agent_collections()
    from agent_vector import seed_exploit_corpus, find_similar_exploits

    seed_exploit_corpus()
    matches = find_similar_exploits(
        tool_name="run_shell",
        capabilities=["shell-exec"],
        framework="langchain",
        evidence="subprocess.run(cmd, shell=True)",
        k=3,
    )
    assert len(matches) >= 1
    # Every match must conform to the API shape (no _id, no embedding).
    for m in matches:
        assert "title" in m and "category" in m and "score" in m
        assert "_id" not in m and "embedding" not in m
        assert isinstance(m["score"], float)


# ── 8C: Critical-finding alerts ────────────────────────────────────────────
def test_alerts_only_fan_out_critical_and_high():
    _reset_agent_collections()
    from agent_alerts import fan_out_critical_alerts, list_alerts

    findings = [
        {
            "type": "DANGEROUS_TOOL_CAPABILITY",
            "severity": "critical",
            "title": "shell tool",
            "line_number": 1,
        },
        {
            "type": "LLM_OUTPUT_TO_EXEC",
            "severity": "high",
            "title": "eval(LLM)",
            "line_number": 2,
        },
        {
            "type": "TOOL_EXCESSIVE_SCOPE",
            "severity": "medium",
            "title": "medium — should NOT alert",
            "line_number": 3,
        },
        {
            "type": "SECRET_IN_PROMPT",  # not agentic — should be ignored
            "severity": "critical",
            "title": "key in prompt",
            "line_number": 4,
        },
    ]
    fan_out_critical_alerts(
        findings, scan_id="sX", repo_full_name="acme/agent", source="github"
    )
    rows = list_alerts(repo_full_name="acme/agent")
    types = sorted(r["finding_type"] for r in rows)
    assert types == ["DANGEROUS_TOOL_CAPABILITY", "LLM_OUTPUT_TO_EXEC"]
    # All written by the Python pipeline (no Atlas trigger in tests).
    assert all(r.get("_written_by") == "python_pipeline" for r in rows)


def test_alerts_dedupe_by_signature():
    _reset_agent_collections()
    from agent_alerts import fan_out_critical_alerts, list_alerts

    finding = {
        "type": "DANGEROUS_TOOL_CAPABILITY",
        "severity": "critical",
        "title": "shell tool",
        "evidence": "subprocess.run(cmd)",
        "line_number": 1,
    }
    inserted_first = fan_out_critical_alerts(
        [finding], scan_id="s1", repo_full_name="acme/agent"
    )
    inserted_second = fan_out_critical_alerts(
        [finding], scan_id="s2", repo_full_name="acme/agent"
    )
    assert len(inserted_first) == 1
    assert len(inserted_second) == 0
    rows = list_alerts(repo_full_name="acme/agent")
    assert len(rows) == 1
    assert int(rows[0].get("occurrences") or 0) >= 2


def test_alert_acknowledge_flow():
    _reset_agent_collections()
    from agent_alerts import fan_out_critical_alerts, list_alerts, acknowledge

    inserted = fan_out_critical_alerts(
        [
            {
                "type": "LLM_OUTPUT_TO_SHELL",
                "severity": "critical",
                "title": "eval shell",
                "line_number": 1,
            }
        ],
        scan_id="sA",
        repo_full_name="acme/agent",
    )
    assert inserted, "alert should have been inserted"
    alert_id = str(inserted[0]["_id"])

    assert acknowledge(alert_id, by="amlan@ut.edu") is True
    assert acknowledge("not-a-real-id", by="x") is False
    rows = list_alerts(repo_full_name="acme/agent", acknowledged=True)
    assert len(rows) == 1
    assert rows[0]["acknowledged_by"] == "amlan@ut.edu"


# ── 8D: Time-series snapshot ───────────────────────────────────────────────
def test_timeline_only_writes_when_agentic_findings_exist():
    _reset_agent_collections()
    from agent_timeline import snapshot_scan

    none_doc = snapshot_scan(
        [{"type": "SECRET_IN_PROMPT", "severity": "critical"}],
        scan_id="s1",
        repo_full_name="acme/agent",
    )
    assert none_doc is None

    written = snapshot_scan(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "line_number": 1,
            }
        ],
        scan_id="s2",
        repo_full_name="acme/agent",
    )
    assert written is not None
    assert col(C.AGENT_SURFACE_TIMELINE).count_documents({}) == 1


def test_timeline_window_returns_rolling_avg_and_trend():
    _reset_agent_collections()
    from agent_timeline import snapshot_scan, timeline_window

    base_findings = [
        {"type": "DANGEROUS_TOOL_CAPABILITY", "severity": "critical", "line_number": 1},
    ]
    snapshot_scan(base_findings, scan_id="s1", repo_full_name="acme/agent")
    snapshot_scan(
        base_findings
        + [
            {
                "type": "TOOL_PARAM_TO_SHELL",
                "severity": "critical",
                "line_number": 2,
            },
            {
                "type": "LLM_OUTPUT_TO_EXEC",
                "severity": "critical",
                "line_number": 3,
            },
        ],
        scan_id="s2",
        repo_full_name="acme/agent",
    )

    out = timeline_window(repo_full_name="acme/agent", days=30)
    assert len(out["points"]) == 2
    # Both rolling fields must exist on every point.
    for p in out["points"]:
        assert "rolling_7d_risk" in p
        assert "rolling_7d_tools" in p
    # Trend should be non-decreasing risk between scans.
    assert out["trend"]["risk_delta"] >= 0
    assert out["trend"]["window_days"] == 30


# ── 8E: Hybrid $rankFusion over agent_tools ────────────────────────────────
def test_hybrid_search_over_agent_tools_returns_fusion_scores():
    _reset_agent_collections()
    from agent_registry import persist_tools_from_findings
    from hybrid_search import hybrid_search

    persist_tools_from_findings(
        [
            {
                "type": "TOOL_PARAM_TO_SQL",
                "severity": "critical",
                "title": "Tool 'query_db' runs raw SQL",
                "evidence": "@tool\ndef query_db(sql): cursor.execute(sql)",
                "line_number": 12,
            }
        ],
        repo_full_name="acme/agent",
        scan_id="s1",
    )
    persist_tools_from_findings(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "title": "Tool 'run_shell'",
                "evidence": "@tool\ndef run_shell(cmd): subprocess.run(cmd)",
                "line_number": 22,
            }
        ],
        repo_full_name="acme/agent",
        scan_id="s2",
    )

    res = hybrid_search("sql", k=5, collection=C.AGENT_TOOLS)
    assert len(res) >= 1
    top = res[0]
    assert "fusion_score" in top
    # 'sql' should rank query_db at the top via the regex side.
    assert top.get("tool_name") == "query_db"


def test_hybrid_search_back_compat_for_scans_collection():
    _reset_agent_collections()
    import repositories as repos
    from hybrid_search import hybrid_search

    repos.insert_scan(
        {
            "input_text": "subprocess.run(cmd, shell=True)",
            "risk_score": 80,
            "findings": [
                {
                    "type": "X",
                    "title": "shell injection vulnerability",
                    "severity": "critical",
                    "evidence": "subprocess.run",
                }
            ],
            "counts": {"static": 1, "ai": 0, "total": 1},
            "source": "web",
        }
    )
    res = hybrid_search("shell injection", k=5)  # no collection kwarg
    assert len(res) >= 1
    assert "fusion_score" in res[0]


# ── End-to-end: /api/scan populates everything ─────────────────────────────
def test_scan_endpoint_populates_agent_artifacts(client, mock_ai_scan):
    """A scan that yields agentic findings (the AI mock returns 2) should
    write to the tool registry, fan out alerts, and snapshot the timeline."""
    _reset_agent_collections()

    payload = {"text": "@tool\ndef run_shell(cmd):\n    subprocess.run(cmd)\n"}
    r = client.post("/api/scan", json=payload)
    assert r.status_code == 200, r.text

    # Tool registry got at least one row from the AI-derived findings.
    assert col(C.AGENT_TOOLS).count_documents({}) >= 1

    # Both AI findings (DANGEROUS_TOOL_CAPABILITY + LLM_OUTPUT_TO_EXEC) are
    # critical and agentic — both should land in agent_alerts.
    alert_types = {a["finding_type"] for a in col(C.AGENT_ALERTS).find({})}
    assert "DANGEROUS_TOOL_CAPABILITY" in alert_types
    assert "LLM_OUTPUT_TO_EXEC" in alert_types

    # Timeline snapshot exists with non-zero agentic risk score.
    snaps = list(col(C.AGENT_SURFACE_TIMELINE).find({}))
    assert len(snaps) == 1
    assert int(snaps[0].get("agent_risk_score") or 0) > 0


# ── API contract smoke tests for /api/v2/agent-* endpoints ─────────────────
def test_v2_agent_tools_endpoints_basic_contract(client):
    _reset_agent_collections()
    from agent_registry import persist_tools_from_findings

    persist_tools_from_findings(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "title": "Tool 'run_shell'",
                "evidence": "@tool\ndef run_shell(cmd):",
                "line_number": 1,
            }
        ],
        repo_full_name="acme/agent",
        scan_id="s1",
    )

    r = client.get("/api/v2/agent-tools")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert any(t["tool_name"] == "run_shell" for t in data["tools"])

    r = client.get("/api/v2/agent-tools/aggregations/capabilities")
    assert r.status_code == 200
    assert "capabilities" in r.json()

    r = client.get("/api/v2/agent-tools/aggregations/frameworks")
    assert r.status_code == 200
    assert "frameworks" in r.json()


def test_v2_agent_alerts_endpoint(client):
    _reset_agent_collections()
    from agent_alerts import fan_out_critical_alerts

    fan_out_critical_alerts(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "title": "shell tool",
                "line_number": 1,
            }
        ],
        scan_id="sX",
        repo_full_name="acme/agent",
        source="github",
    )

    r = client.get("/api/v2/agent-alerts")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert "trigger_status" in data
    assert data["trigger_status"]["mongomock_mode"] is True


def test_v2_exploit_corpus_seed_and_similar(client):
    _reset_agent_collections()
    r = client.post("/api/v2/agent-tools/exploit-corpus/seed")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 10

    r = client.post(
        "/api/v2/agent-tools/similar-exploits",
        json={
            "tool_name": "delete_file",
            "capabilities": ["filesystem-write", "unbounded-scope"],
            "framework": "langchain",
            "evidence": "os.remove(path)",
            "k": 3,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "matches" in body
    assert body["backend"] in ("local_cosine", "atlas_vector_search")


def test_v2_agent_surface_timeline_endpoint(client):
    _reset_agent_collections()
    from agent_timeline import snapshot_scan

    snapshot_scan(
        [
            {
                "type": "DANGEROUS_TOOL_CAPABILITY",
                "severity": "critical",
                "line_number": 1,
            }
        ],
        scan_id="s1",
        repo_full_name="acme/agent",
    )
    r = client.get("/api/v2/agent-surface-timeline?repo=acme/agent&days=7")
    assert r.status_code == 200
    body = r.json()
    assert "points" in body and "trend" in body
    assert len(body["points"]) >= 1
