import pytest

from policy import (
    EXAMPLE_POLICY_YAML,
    PolicyError,
    apply_policy,
    default_policy,
    parse_policy,
    render_policy_summary,
)


def test_parse_empty_returns_defaults():
    policy, warnings = parse_policy("")
    assert policy == default_policy()
    assert warnings == []

    policy2, _ = parse_policy(None)
    assert policy2 == default_policy()


def test_parse_example_is_valid():
    policy, warnings = parse_policy(EXAMPLE_POLICY_YAML)
    assert warnings == []
    assert policy["min_score"] == 70
    assert policy["block_if"] == {"critical": 1, "high": 3}
    assert "DATA_LEAKAGE" in policy["ignore"]["types"]
    assert policy["severity_overrides"]["OVERLY_PERMISSIVE"] == "low"


def test_parse_rejects_non_mapping():
    with pytest.raises(PolicyError):
        parse_policy("- not a mapping")


def test_parse_rejects_invalid_yaml():
    with pytest.raises(PolicyError):
        parse_policy("min_score: [unclosed")


def test_parse_warns_on_unknown_keys_and_bad_types():
    yaml_text = """
    min_score: "not-a-number"
    block_if:
      bogus_sev: 2
      high: nan
    ignore: "not a mapping"
    severity_overrides:
      SOME_TYPE: purple
    random_key: hi
    """
    policy, warnings = parse_policy(yaml_text)
    joined = "\n".join(warnings)
    assert "min_score" in joined
    assert "bogus_sev" in joined
    assert "random_key" in joined
    # invalid severity override dropped
    assert policy["severity_overrides"] == {}


def test_apply_policy_passes_when_clean():
    policy, _ = parse_policy("min_score: 70")
    decision = apply_policy(policy, [], 0)
    assert decision["passed"] is True
    assert decision["effective_score"] == 0


def test_apply_policy_blocks_on_min_score():
    policy, _ = parse_policy("min_score: 50")
    decision = apply_policy(policy, [], 60)
    assert decision["passed"] is False
    assert any("min_score" in r for r in decision["reasons"])


def test_apply_policy_blocks_on_block_if_counts():
    policy, _ = parse_policy(
        """
        min_score: 999
        block_if:
          critical: 1
        """
    )
    findings = [
        {"type": "SECRET_IN_PROMPT", "severity": "critical", "confidence": 0.95}
    ]
    decision = apply_policy(policy, findings, 40)
    assert decision["passed"] is False
    assert any("block_if.critical" in r for r in decision["reasons"])


def test_apply_policy_ignore_types_drops_finding_and_recomputes_score():
    policy, _ = parse_policy(
        """
        min_score: 50
        ignore:
          types:
            - DATA_LEAKAGE
        """
    )
    findings = [
        {"type": "DATA_LEAKAGE", "severity": "high", "confidence": 0.85},
        {"type": "SECRET_IN_PROMPT", "severity": "medium", "confidence": 0.9},
    ]
    decision = apply_policy(policy, findings, 28)
    effective_types = {f["type"] for f in decision["effective_findings"]}
    assert "DATA_LEAKAGE" not in effective_types
    # Only the remaining medium (weight 8) contributes after ignore.
    assert decision["effective_score"] == 8
    assert decision["passed"] is True


def test_apply_policy_severity_override_demotes():
    policy, _ = parse_policy(
        """
        min_score: 50
        severity_overrides:
          OVERLY_PERMISSIVE: low
        """
    )
    findings = [
        {"type": "OVERLY_PERMISSIVE", "severity": "critical", "confidence": 0.8}
    ]
    decision = apply_policy(policy, findings, 40)
    # After override -> low (weight 3)
    assert decision["effective_score"] == 3
    assert decision["counts"]["low"] == 1
    assert decision["counts"]["critical"] == 0
    assert decision["passed"] is True


def test_render_policy_summary_contains_verdict():
    policy, _ = parse_policy("min_score: 50")
    decision = apply_policy(policy, [], 60)
    md = render_policy_summary(decision)
    assert "policy blocked" in md
    assert "min_score 50" in md
