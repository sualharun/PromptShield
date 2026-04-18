"""Tests for the evaluation harness and regression detection (Mongo-backed)."""

import pytest

from eval_harness import run_eval, list_eval_runs


@pytest.fixture(autouse=True)
def _setup():
    from mongo import C, col

    col(C.EVAL_RUNS).delete_many({})


def test_run_eval_returns_metrics():
    result = run_eval()
    assert "f1" in result
    assert "precision" in result
    assert "recall" in result
    assert "accuracy" in result
    assert "eval_run_id" in result
    assert result["regression"] is False
    assert result["previous_f1"] is None


def test_eval_persists_run():
    run_eval()
    runs = list_eval_runs()
    assert len(runs) == 1
    assert runs[0]["scanner_version"] == "0.3.0"


def test_multiple_evals_no_regression():
    run_eval()
    result2 = run_eval()
    assert result2["regression"] is False
    assert result2["previous_f1"] is not None
    runs = list_eval_runs()
    assert len(runs) == 2


def test_regression_detected_on_f1_drop():
    from datetime import datetime, timezone

    from mongo import C, col

    col(C.EVAL_RUNS).insert_one(
        {
            "scanner_version": "0.2.0",
            "total_samples": 10,
            "true_positives": 8,
            "true_negatives": 1,
            "false_positives": 0,
            "false_negatives": 1,
            "precision": 1.0,
            "recall": 0.89,
            "f1": 0.94,
            "accuracy": 0.90,
            "run_at": datetime.now(timezone.utc),
        }
    )

    result = run_eval()
    if result["f1"] < 0.93:
        assert result["regression"] is True
        assert len(result["regression_details"]) > 0


def test_list_eval_runs_limit():
    for _ in range(5):
        run_eval()
    runs = list_eval_runs(limit=3)
    assert len(runs) == 3
