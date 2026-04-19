"""Tests for baseline suppression and drift detection — Mongo-backed (v0.4)."""
import pytest

from drift import (
    acknowledge_baseline,
    classify_findings,
    get_drift_summary,
    get_regressions_only,
    update_baseline,
)
from mongo import C, col


@pytest.fixture(autouse=True)
def _setup():
    col(C.BASELINE_FINDINGS).delete_many({})


def _finding(ftype="SECRETS", title="API key", severity="high", evidence="abc123"):
    return {"type": ftype, "title": title, "severity": severity, "evidence": evidence}


def test_classify_all_new():
    findings = [_finding(), _finding(ftype="INJECTION", title="Prompt injection")]
    new, known = classify_findings(None, "org/repo", findings)
    assert len(new) == 2
    assert len(known) == 0
    assert all(f["baseline"] is False for f in new)


def test_classify_after_baseline_update():
    findings = [_finding()]
    update_baseline(None, "org/repo", findings)
    new, known = classify_findings(None, "org/repo", findings)
    assert len(new) == 0
    assert len(known) == 1
    assert known[0]["baseline"] is True


def test_update_baseline_stats():
    findings = [_finding(), _finding(ftype="INJECTION")]
    stats = update_baseline(None, "org/repo", findings)
    assert stats["added"] == 2
    assert stats["updated"] == 0
    assert stats["total_baseline"] == 2

    stats2 = update_baseline(None, "org/repo", findings)
    assert stats2["added"] == 0
    assert stats2["updated"] == 2


def test_acknowledge_baseline():
    update_baseline(None, "org/repo", [_finding()])
    row = col(C.BASELINE_FINDINGS).find_one({"repo_full_name": "org/repo"})
    assert row is not None
    sig = row["signature"]
    result = acknowledge_baseline(None, "org/repo", sig, "tester@co.com")
    assert result is True

    row = col(C.BASELINE_FINDINGS).find_one({"repo_full_name": "org/repo"})
    assert row["acknowledged"] is True
    assert row["acknowledged_by"] == "tester@co.com"


def test_acknowledge_nonexistent():
    result = acknowledge_baseline(None, "org/repo", "nonexistent_sig", "user")
    assert result is False


def test_drift_summary():
    findings = [
        _finding(severity="critical"),
        _finding(ftype="INJECTION", severity="high"),
        _finding(ftype="LEAK", severity="medium"),
    ]
    update_baseline(None, "org/repo", findings)
    summary = get_drift_summary(None, "org/repo")
    assert summary["repo"] == "org/repo"
    assert summary["total_baseline"] == 3
    assert summary["acknowledged"] == 0
    assert summary["unacknowledged"] == 3
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["medium"] == 1


def test_regressions_only():
    old = [_finding()]
    update_baseline(None, "org/repo", old)

    current = [_finding(), _finding(ftype="NEW_TYPE", title="New finding")]
    regressions = get_regressions_only(None, "org/repo", current)
    assert len(regressions) == 1
    assert regressions[0]["type"] == "NEW_TYPE"


def test_cross_repo_isolation():
    update_baseline(None, "org/repo-a", [_finding()])
    new, known = classify_findings(None, "org/repo-b", [_finding()])
    assert len(new) == 1
    assert len(known) == 0
