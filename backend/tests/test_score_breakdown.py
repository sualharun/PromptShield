from score_breakdown import compute_breakdown, render_breakdown_markdown


def test_empty_findings_all_clean():
    out = compute_breakdown([], static_count=0, ai_count=0)
    keys = [c["key"] for c in out["categories"]]
    assert keys == ["secrets", "injection", "role", "leakage", "tools", "output"]
    for c in out["categories"]:
        assert c["score"] == 100
        assert c["finding_count"] == 0
        assert c["confidence"] == "high"
    sources = [s["source"] for s in out["signals"]]
    assert sources == ["static", "ai", "dataflow"]


def test_secret_bucket_drops_score():
    findings = [
        {
            "type": "SECRET_IN_PROMPT",
            "severity": "critical",
            "title": "Hardcoded secret",
            "confidence": 0.95,
        }
    ]
    out = compute_breakdown(findings, static_count=1, ai_count=0)
    secrets = next(c for c in out["categories"] if c["key"] == "secrets")
    assert secrets["score"] == 60
    assert secrets["finding_count"] == 1
    assert secrets["confidence"] == "high"
    assert "Hardcoded secret" in secrets["why"]
    injection = next(c for c in out["categories"] if c["key"] == "injection")
    assert injection["score"] == 100


def test_category_routing_for_all_scanner_types():
    findings = [
        {"type": "DIRECT_INJECTION", "severity": "critical", "title": "A", "confidence": 0.9},
        {"type": "INDIRECT_INJECTION", "severity": "high", "title": "B", "confidence": 0.85},
        {"type": "ROLE_CONFUSION", "severity": "high", "title": "C", "confidence": 0.85},
        {"type": "OVERLY_PERMISSIVE", "severity": "medium", "title": "D", "confidence": 0.8},
        {"type": "DATA_LEAKAGE", "severity": "high", "title": "E", "confidence": 0.85},
        {"type": "SYSTEM_PROMPT_EXPOSED", "severity": "high", "title": "F", "confidence": 0.75},
    ]
    out = compute_breakdown(findings, static_count=6, ai_count=0)
    by_key = {c["key"]: c for c in out["categories"]}
    assert by_key["injection"]["finding_count"] == 2
    assert by_key["role"]["finding_count"] == 2
    assert by_key["secrets"]["finding_count"] == 1
    assert by_key["leakage"]["finding_count"] == 1
    # system prompt finding has confidence 0.75 -> medium
    assert by_key["leakage"]["confidence"] == "medium"


def test_signal_weights_reflect_static_vs_ai_split():
    out = compute_breakdown([], static_count=3, ai_count=1)
    static = next(s for s in out["signals"] if s["source"] == "static")
    ai = next(s for s in out["signals"] if s["source"] == "ai")
    assert static["weight_pct"] == 75
    assert ai["weight_pct"] == 25
    assert ai["confidence"] == "medium"


def test_ai_signal_low_confidence_when_no_ai():
    out = compute_breakdown([], static_count=2, ai_count=0)
    ai = next(s for s in out["signals"] if s["source"] == "ai")
    assert ai["confidence"] == "low"
    assert ai["weight_pct"] == 0


def test_markdown_render_includes_every_category():
    out = compute_breakdown([], static_count=1, ai_count=1)
    md = render_breakdown_markdown(out)
    assert "Score breakdown" in md
    assert "Secrets & PII" in md
    assert "Prompt injection" in md
    assert "Role confusion" in md
    assert "System-prompt leak" in md


def test_markdown_empty_breakdown_returns_empty_string():
    assert render_breakdown_markdown({}) == ""
    assert render_breakdown_markdown(None) == ""
