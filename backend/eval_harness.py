"""Evaluation harness: runs benchmarks and tracks regressions across versions.

Wraps the existing benchmark.evaluate() and adds:
- Persistent eval run history
- Regression detection against the previous run
- Per-sample diff reporting
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from benchmark import evaluate as run_benchmark_raw
from database import SessionLocal
from models import EvalRun


SCANNER_VERSION = "0.3.0"


def run_eval(db: Optional[Session] = None) -> Dict:
    """Execute the benchmark suite and persist results."""
    result = run_benchmark_raw()
    if "f1_score" in result and "f1" not in result:
        result["f1"] = result["f1_score"]
    if "results" in result and "misclassifications" not in result:
        result["misclassifications"] = result["results"]
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        previous = (
            db.query(EvalRun)
            .order_by(EvalRun.run_at.desc())
            .first()
        )

        regression = False
        regression_details = []
        if previous:
            if result["f1"] < previous.f1 - 0.01:
                regression = True
                regression_details.append(
                    f"F1 dropped from {previous.f1:.3f} to {result['f1']:.3f}"
                )
            if result["precision"] < previous.precision - 0.02:
                regression = True
                regression_details.append(
                    f"Precision dropped from {previous.precision:.3f} to {result['precision']:.3f}"
                )
            if result["recall"] < previous.recall - 0.02:
                regression = True
                regression_details.append(
                    f"Recall dropped from {previous.recall:.3f} to {result['recall']:.3f}"
                )

        run = EvalRun(
            scanner_version=SCANNER_VERSION,
            total_samples=result["total_samples"],
            true_positives=result["true_positives"],
            true_negatives=result["true_negatives"],
            false_positives=result["false_positives"],
            false_negatives=result["false_negatives"],
            precision=result["precision"],
            recall=result["recall"],
            f1=result["f1"],
            accuracy=result["accuracy"],
            details_json=json.dumps(result.get("misclassifications", [])),
            regression_from_previous=regression,
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        return {
            **result,
            "eval_run_id": run.id,
            "scanner_version": SCANNER_VERSION,
            "regression": regression,
            "regression_details": regression_details,
            "previous_f1": previous.f1 if previous else None,
            "previous_precision": previous.precision if previous else None,
            "previous_recall": previous.recall if previous else None,
        }
    finally:
        if close_db:
            db.close()


def list_eval_runs(db: Session, limit: int = 20) -> List[Dict]:
    """Return recent eval runs for the regression chart."""
    runs = (
        db.query(EvalRun)
        .order_by(EvalRun.run_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "run_at": r.run_at.isoformat(),
            "scanner_version": r.scanner_version,
            "f1": r.f1,
            "precision": r.precision,
            "recall": r.recall,
            "accuracy": r.accuracy,
            "total_samples": r.total_samples,
            "tp": r.true_positives,
            "tn": r.true_negatives,
            "fp": r.false_positives,
            "fn": r.false_negatives,
            "regression": r.regression_from_previous,
        }
        for r in runs
    ]
