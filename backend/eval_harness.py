"""Evaluation harness: runs benchmarks and tracks regressions across versions.

v0.4: Mongo-backed (`eval_runs` collection). Wraps `benchmark.evaluate()` and
adds:
- Persistent eval run history
- Regression detection against the previous run
- Per-sample diff reporting

The legacy `db` parameter is accepted (and ignored) so callers don't have to
all migrate at once.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from benchmark import evaluate as run_benchmark_raw
from mongo import C, col

SCANNER_VERSION = "0.3.0"


def _last_run() -> Optional[dict]:
    cursor = col(C.EVAL_RUNS).find().sort("run_at", -1).limit(1)
    return next(iter(cursor), None)


def run_eval(db: Any = None) -> Dict:
    """Execute the benchmark suite and persist results."""
    result = dict(run_benchmark_raw())
    if "f1_score" in result and "f1" not in result:
        result["f1"] = result["f1_score"]
    if "results" in result and "misclassifications" not in result:
        result["misclassifications"] = result["results"]
    # `benchmark.evaluate()` historically only returned (precision, recall, f1).
    # Backfill missing aggregate counts so downstream persistence + tests work
    # against either the legacy or the extended return shape.
    result.setdefault("accuracy", 0.0)
    result.setdefault("total_samples", 0)
    result.setdefault("true_positives", 0)
    result.setdefault("true_negatives", 0)
    result.setdefault("false_positives", 0)
    result.setdefault("false_negatives", 0)
    result.setdefault("misclassifications", [])

    previous = _last_run()
    regression = False
    regression_details: list[str] = []
    if previous:
        prev_f1 = float(previous.get("f1") or 0.0)
        prev_prec = float(previous.get("precision") or 0.0)
        prev_rec = float(previous.get("recall") or 0.0)
        if result["f1"] < prev_f1 - 0.01:
            regression = True
            regression_details.append(
                f"F1 dropped from {prev_f1:.3f} to {result['f1']:.3f}"
            )
        if result["precision"] < prev_prec - 0.02:
            regression = True
            regression_details.append(
                f"Precision dropped from {prev_prec:.3f} to {result['precision']:.3f}"
            )
        if result["recall"] < prev_rec - 0.02:
            regression = True
            regression_details.append(
                f"Recall dropped from {prev_rec:.3f} to {result['recall']:.3f}"
            )

    doc = {
        "scanner_version": SCANNER_VERSION,
        "total_samples": int(result["total_samples"]),
        "true_positives": int(result["true_positives"]),
        "true_negatives": int(result["true_negatives"]),
        "false_positives": int(result["false_positives"]),
        "false_negatives": int(result["false_negatives"]),
        "precision": float(result["precision"]),
        "recall": float(result["recall"]),
        "f1": float(result["f1"]),
        "accuracy": float(result["accuracy"]),
        "details": result.get("misclassifications", []),
        "regression_from_previous": regression,
        "run_at": datetime.now(timezone.utc),
    }
    res = col(C.EVAL_RUNS).insert_one(doc)
    doc["_id"] = res.inserted_id

    return {
        **result,
        "eval_run_id": str(doc["_id"]),
        "scanner_version": SCANNER_VERSION,
        "regression": regression,
        "regression_details": regression_details,
        "previous_f1": previous.get("f1") if previous else None,
        "previous_precision": previous.get("precision") if previous else None,
        "previous_recall": previous.get("recall") if previous else None,
    }


def list_eval_runs(db: Any = None, limit: int = 20) -> List[Dict]:
    """Return recent eval runs for the regression chart."""
    cursor = col(C.EVAL_RUNS).find().sort("run_at", -1).limit(limit)
    out: list[dict] = []
    for r in cursor:
        run_at = r.get("run_at") or datetime.now(timezone.utc)
        out.append(
            {
                "id": str(r.get("_id")),
                "run_at": run_at.isoformat() if hasattr(run_at, "isoformat") else str(run_at),
                "scanner_version": r.get("scanner_version") or SCANNER_VERSION,
                "f1": r.get("f1"),
                "precision": r.get("precision"),
                "recall": r.get("recall"),
                "accuracy": r.get("accuracy"),
                "total_samples": r.get("total_samples"),
                "tp": r.get("true_positives"),
                "tn": r.get("true_negatives"),
                "fp": r.get("false_positives"),
                "fn": r.get("false_negatives"),
                "regression": bool(r.get("regression_from_previous", False)),
            }
        )
    return out
