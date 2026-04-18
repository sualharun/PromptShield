"""Tests that the benchmark suite itself runs and meets minimum accuracy."""

from benchmark import SAMPLES, evaluate


def test_benchmark_has_100_samples():
    assert len(SAMPLES) == 100
    vuln = sum(1 for s in SAMPLES if s[2] == "vulnerable")
    safe = sum(1 for s in SAMPLES if s[2] == "safe")
    assert vuln == 50
    assert safe == 50


def test_benchmark_unique_ids():
    ids = [s[0] for s in SAMPLES]
    assert len(ids) == len(set(ids))


def test_benchmark_precision_above_90():
    r = evaluate()
    assert r["precision"] >= 0.90, f"precision {r['precision']} below 90%"


def test_benchmark_recall_above_90():
    r = evaluate()
    assert r["recall"] >= 0.90, f"recall {r['recall']} below 90%"


def test_benchmark_f1_above_90():
    r = evaluate()
    assert r["f1_score"] >= 0.90, f"F1 {r['f1_score']} below 90%"
