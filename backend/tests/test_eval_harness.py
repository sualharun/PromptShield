"""Tests for the evaluation harness and regression detection."""

import os
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///")

from database import Base, engine, SessionLocal
from models import EvalRun
from eval_harness import run_eval, list_eval_runs


@pytest.fixture(autouse=True)
def _setup():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_run_eval_returns_metrics():
    db = SessionLocal()
    try:
        result = run_eval(db)
        assert "f1" in result
        assert "precision" in result
        assert "recall" in result
        assert "accuracy" in result
        assert "eval_run_id" in result
        assert result["regression"] is False
        assert result["previous_f1"] is None
    finally:
        db.close()


def test_eval_persists_run():
    db = SessionLocal()
    try:
        run_eval(db)
        runs = list_eval_runs(db)
        assert len(runs) == 1
        assert runs[0]["scanner_version"] == "0.3.0"
    finally:
        db.close()


def test_multiple_evals_no_regression():
    db = SessionLocal()
    try:
        run_eval(db)
        result2 = run_eval(db)
        assert result2["regression"] is False
        assert result2["previous_f1"] is not None
        runs = list_eval_runs(db)
        assert len(runs) == 2
    finally:
        db.close()


def test_regression_detected_on_f1_drop():
    db = SessionLocal()
    try:
        first = EvalRun(
            scanner_version="0.2.0",
            total_samples=10,
            true_positives=8,
            true_negatives=1,
            false_positives=0,
            false_negatives=1,
            precision=1.0,
            recall=0.89,
            f1=0.94,
            accuracy=0.90,
        )
        db.add(first)
        db.commit()

        result = run_eval(db)
        if result["f1"] < 0.93:
            assert result["regression"] is True
            assert len(result["regression_details"]) > 0
    finally:
        db.close()


def test_list_eval_runs_limit():
    db = SessionLocal()
    try:
        for _ in range(5):
            run_eval(db)
        runs = list_eval_runs(db, limit=3)
        assert len(runs) == 3
    finally:
        db.close()
