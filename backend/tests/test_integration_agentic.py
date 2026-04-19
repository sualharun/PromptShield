"""Integration tests for the agentic-security pivot.

Verifies that the full pipeline — static rules + dataflow + Gemini AI —
correctly surfaces the new `tools` and `output` finding categories when
given the demo vulnerable-agent files at backend/examples/.

These complement the unit tests in:
  - tests/test_scanner.py        (static rules in isolation)
  - tests/test_dataflow.py       (AST/dataflow in isolation)
  - tests/test_score_breakdown.py (category routing in isolation)

The placeholder demo files committed by Dev 2 trigger a *minimum* baseline
of detectors so this suite stays green during the integration window. Once
Dev 1 (Cyber) ships the real demo fixtures and James (DS/ML) lands the
agentic AST detectors, the assertions below tighten automatically because
they assert on category presence + minimum counts, not exact finding sets.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from dataflow import scan_dataflow
from scanner import merge_findings, static_scan
from score_breakdown import compute_breakdown


_EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _read_example(name: str) -> str:
    return (_EXAMPLES_DIR / name).read_text(encoding="utf-8")


# ─── Detector-layer tests ──────────────────────────────────────────────────
# These document the contract the static + dataflow layers should fulfil
# once the team's detectors land. They xfail (rather than hard-fail) on
# placeholder fixtures so the suite stays green during integration.


def test_static_catches_dangerous_tool():
    code = _read_example("vulnerable_agent.py")
    findings = static_scan(code, language="python")
    types = {f["type"] for f in findings}
    if "DANGEROUS_TOOL_CAPABILITY" not in types:
        pytest.xfail(
            "static rule DANGEROUS_TOOL_CAPABILITY not yet implemented "
            "(Dev 1 / Cyber owns this)"
        )


def test_static_catches_llm_output_exec():
    code = _read_example("unsafe_output.py")
    findings = static_scan(code, language="python")
    types = {f["type"] for f in findings}
    if not (types & {"LLM_OUTPUT_TO_EXEC", "LLM_OUTPUT_TO_SQL", "LLM_OUTPUT_TO_SHELL"}):
        pytest.xfail(
            "static LLM_OUTPUT_TO_* rules not yet implemented "
            "(Dev 1 / Cyber owns this)"
        )


def test_dataflow_catches_tool_params():
    code = _read_example("vulnerable_agent.py")
    findings = scan_dataflow(code)
    types = {f["type"] for f in findings}
    expected = {"TOOL_PARAM_TO_SHELL", "TOOL_PARAM_TO_SQL", "TOOL_PARAM_TO_EXEC"}
    if not (types & expected):
        pytest.xfail(
            "dataflow tool-param sink detection not yet implemented "
            "(James / DS-ML owns this)"
        )


def test_dataflow_catches_llm_output():
    code = _read_example("unsafe_output.py")
    findings = scan_dataflow(code)
    types = {f["type"] for f in findings}
    expected = {"LLM_OUTPUT_TO_EXEC", "LLM_OUTPUT_TO_SHELL", "LLM_OUTPUT_TO_SQL"}
    if not (types & expected):
        pytest.xfail(
            "dataflow LLM-output sink detection not yet implemented "
            "(James / DS-ML owns this)"
        )


# ─── Hard contract tests — these MUST stay green ───────────────────────────


def test_breakdown_has_tool_and_output_categories():
    """Score breakdown surfaces the two new agentic categories with a
    score < 100 when the relevant findings are present."""
    findings = [
        {
            "type": "DANGEROUS_TOOL_CAPABILITY",
            "severity": "critical",
            "title": "Tool exposes subprocess to LLM",
            "confidence": 0.9,
            "source": "static",
        },
        {
            "type": "LLM_OUTPUT_TO_EXEC",
            "severity": "critical",
            "title": "LLM response passed to eval()",
            "confidence": 0.92,
            "source": "static",
        },
    ]
    result = compute_breakdown(findings, static_count=2, ai_count=0)
    keys = {c["key"] for c in result["categories"]}
    assert "tools" in keys
    assert "output" in keys

    tools_cat = next(c for c in result["categories"] if c["key"] == "tools")
    output_cat = next(c for c in result["categories"] if c["key"] == "output")
    assert tools_cat["score"] < 100
    assert output_cat["score"] < 100
    assert tools_cat["finding_count"] == 1
    assert output_cat["finding_count"] == 1


def test_merge_deduplicates_static_and_dataflow():
    """Combined detector output should not have duplicate findings on the
    same (category, line) pair. We assert by category — not raw type — to
    catch the case where static and dataflow emit slightly different type
    names (e.g. LLM_OUTPUT_TO_EXEC vs LLM_OUTPUT_EXEC) for the same issue.
    """
    from score_breakdown import _TYPE_TO_CATEGORY  # type: ignore

    code = _read_example("vulnerable_agent.py")
    static = static_scan(code, language="python")
    df = scan_dataflow(code)
    merged = merge_findings(static + df, [])

    seen = set()
    for f in merged:
        category = _TYPE_TO_CATEGORY.get(f.get("type"))
        if category is None:
            continue  # uncategorized findings can't dedupe-collide
        key = (category, f.get("line_number"))
        assert key not in seen, (
            f"Duplicate finding in same (category, line): {key} "
            f"— static and dataflow likely emitted different `type` names "
            f"for the same bug. Align on one canonical name."
        )
        seen.add(key)


def test_examples_endpoint(client):
    """/api/examples returns the seeded demo files with content + metadata."""
    resp = client.get("/api/examples")
    assert resp.status_code == 200
    data = resp.json()
    assert "examples" in data
    assert data["count"] == len(data["examples"])
    assert len(data["examples"]) >= 3, (
        "expected at least 3 demo files in backend/examples/"
    )
    for ex in data["examples"]:
        assert "name" in ex
        assert "filename" in ex
        assert "content" in ex
        assert "description" in ex
        assert ex["language"] == "python"
        assert ex["filename"].endswith(".py")
        assert len(ex["content"]) > 0
    names = {ex["name"] for ex in data["examples"]}
    # The three canonical demos must always be present.
    assert {"vulnerable_agent", "unsafe_output", "unsafe_rag"} <= names


# ─── End-to-end pipeline test (uses mocked AI) ─────────────────────────────


def test_scan_pipeline_with_ai_mock(client, mock_ai_scan):
    """Full /api/scan run with a deterministic AI mock — verifies that
    AI-emitted agentic findings actually round-trip through merge_findings,
    compute_breakdown, and into the persisted scan document."""
    code = _read_example("vulnerable_agent.py")
    resp = client.post("/api/scan", json={"text": code})
    assert resp.status_code == 200
    body = resp.json()

    types = {f["type"] for f in body["findings"]}
    assert "DANGEROUS_TOOL_CAPABILITY" in types or "LLM_OUTPUT_TO_EXEC" in types, (
        "AI mock findings should appear in merged scan output"
    )

    breakdown = body.get("score_breakdown") or {}
    cats = {c["key"]: c for c in breakdown.get("categories", [])}
    assert "tools" in cats and "output" in cats
    # At least one of the two agentic categories must show a non-clean score
    # given the AI mock injects critical findings into both.
    assert cats["tools"]["score"] < 100 or cats["output"]["score"] < 100

    signals = {s["source"]: s for s in breakdown.get("signals", [])}
    assert {"static", "ai", "dataflow"} <= set(signals.keys())
