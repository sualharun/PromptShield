"""Tests for baseline suppression and drift detection."""

import os
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///")

from database import Base, engine, init_db
from models import BaselineFinding
from database import SessionLocal
from drift import (
    classify_findings,
    update_baseline,
    acknowledge_baseline,
    get_drift_summary,
    get_regressions_only,
)


@pytest.fixture(autouse=True)
def _setup():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _db():
    return SessionLocal()


def _finding(ftype="SECRETS", title="API key", severity="high", evidence="abc123"):
    return {"type": ftype, "title": title, "severity": severity, "evidence": evidence}


def test_classify_all_new():
    db = _db()
    try:
        findings = [_finding(), _finding(ftype="INJECTION", title="Prompt injection")]
        new, known = classify_findings(db, "org/repo", findings)
        assert len(new) == 2
        assert len(known) == 0
        assert all(f["baseline"] is False for f in new)
    finally:
        db.close()


def test_classify_after_baseline_update():
    db = _db()
    try:
        findings = [_finding()]
        update_baseline(db, "org/repo", findings)
        new, known = classify_findings(db, "org/repo", findings)
        assert len(new) == 0
        assert len(known) == 1
        assert known[0]["baseline"] is True
    finally:
        db.close()


def test_update_baseline_stats():
    db = _db()
    try:
        findings = [_finding(), _finding(ftype="INJECTION")]
        stats = update_baseline(db, "org/repo", findings)
        assert stats["added"] == 2
        assert stats["updated"] == 0
        assert stats["total_baseline"] == 2

        stats2 = update_baseline(db, "org/repo", findings)
        assert stats2["added"] == 0
        assert stats2["updated"] == 2
    finally:
        db.close()


def test_acknowledge_baseline():
    db = _db()
    try:
        update_baseline(db, "org/repo", [_finding()])
        row = db.query(BaselineFinding).first()
        result = acknowledge_baseline(db, "org/repo", row.signature, "tester@co.com")
        assert result is True

        row = db.query(BaselineFinding).first()
        assert row.acknowledged is True
        assert row.acknowledged_by == "tester@co.com"
    finally:
        db.close()


def test_acknowledge_nonexistent():
    db = _db()
    try:
        result = acknowledge_baseline(db, "org/repo", "nonexistent_sig", "user")
        assert result is False
    finally:
        db.close()


def test_drift_summary():
    db = _db()
    try:
        findings = [
            _finding(severity="critical"),
            _finding(ftype="INJECTION", severity="high"),
            _finding(ftype="LEAK", severity="medium"),
        ]
        update_baseline(db, "org/repo", findings)
        summary = get_drift_summary(db, "org/repo")
        assert summary["repo"] == "org/repo"
        assert summary["total_baseline"] == 3
        assert summary["acknowledged"] == 0
        assert summary["unacknowledged"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
    finally:
        db.close()


def test_regressions_only():
    db = _db()
    try:
        old = [_finding()]
        update_baseline(db, "org/repo", old)

        current = [_finding(), _finding(ftype="NEW_TYPE", title="New finding")]
        regressions = get_regressions_only(db, "org/repo", current)
        assert len(regressions) == 1
        assert regressions[0]["type"] == "NEW_TYPE"
    finally:
        db.close()


def test_cross_repo_isolation():
    db = _db()
    try:
        update_baseline(db, "org/repo-a", [_finding()])
        new, known = classify_findings(db, "org/repo-b", [_finding()])
        assert len(new) == 1
        assert len(known) == 0
    finally:
        db.close()
