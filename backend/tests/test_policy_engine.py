"""Tests for the enhanced policy engine: versioning, simulation, and diff."""

import pytest

from policy_engine import (
    save_policy_version,
    get_active_policy,
    list_policy_versions,
    simulate_policy,
    diff_policies,
)


@pytest.fixture(autouse=True)
def _setup():
    from mongo import C, col
    col(C.POLICY_VERSIONS).delete_many({})


SIMPLE_POLICY = """
min_score: 70
block_if:
  critical: 1
  high: 3
"""

UPDATED_POLICY = """
min_score: 80
block_if:
  critical: 1
  high: 2
ignore:
  types:
    - SECRETS
"""


def test_save_and_retrieve_version():
    result = save_policy_version(None, SIMPLE_POLICY)
    assert result["version"] == 1
    assert result["policy"]["min_score"] == 70

    active = get_active_policy(None)
    assert active is not None
    assert active["version"] == 1


def test_version_increment_and_deactivation():
    from mongo import C, col

    save_policy_version(None, SIMPLE_POLICY)
    result2 = save_policy_version(None, UPDATED_POLICY, change_summary="Raised threshold")
    assert result2["version"] == 2

    active = get_active_policy(None)
    assert active["version"] == 2

    old = col(C.POLICY_VERSIONS).find_one(
        {"version": 1, "repo_full_name": None, "org_id": None}
    )
    assert old is not None
    assert bool(old.get("is_active")) is False


def test_list_versions():
    save_policy_version(None, SIMPLE_POLICY)
    save_policy_version(None, UPDATED_POLICY)
    versions = list_policy_versions(None)
    assert len(versions) == 2
    assert versions[0]["version"] == 2
    assert versions[1]["version"] == 1


def test_simulate_min_score_fires():
    findings = [
        {"type": "SECRETS", "severity": "high", "title": "Key leak"},
    ]
    result = simulate_policy(SIMPLE_POLICY, findings, risk_score=75)
    trail = result["explanation_trail"]
    min_score_rule = next(r for r in trail if r["rule"] == "min_score")
    assert min_score_rule["fired"] is True


def test_simulate_min_score_does_not_fire():
    result = simulate_policy(SIMPLE_POLICY, [], risk_score=50)
    trail = result["explanation_trail"]
    min_score_rule = next(r for r in trail if r["rule"] == "min_score")
    assert min_score_rule["fired"] is False


def test_simulate_block_if():
    findings = [
        {"type": "SECRETS", "severity": "critical", "title": "Critical leak"},
    ]
    result = simulate_policy(SIMPLE_POLICY, findings, risk_score=90)
    trail = result["explanation_trail"]
    critical_rule = next(r for r in trail if r["rule"] == "block_if.critical")
    assert critical_rule["fired"] is True
    assert critical_rule["actual"] == 1


def test_simulate_ignore_types():
    findings = [
        {"type": "SECRETS", "severity": "high", "title": "Key"},
        {"type": "INJECTION", "severity": "high", "title": "Prompt"},
    ]
    result = simulate_policy(UPDATED_POLICY, findings, risk_score=85)
    trail = result["explanation_trail"]
    ignore_rule = next(r for r in trail if r["rule"] == "ignore.types")
    assert ignore_rule["fired"] is True
    assert ignore_rule["dropped_count"] == 1


def test_diff_policies_detects_changes():
    result = diff_policies(SIMPLE_POLICY, UPDATED_POLICY)
    assert result["has_changes"] is True
    field_names = [c["field"] for c in result["changes"]]
    assert "min_score" in field_names


def test_diff_identical_policies():
    result = diff_policies(SIMPLE_POLICY, SIMPLE_POLICY)
    assert result["has_changes"] is False
    assert len(result["changes"]) == 0
