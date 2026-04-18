"""Tests for observability: metrics, tracing, and SLO tracking."""

from observability import Metrics, Span, Tracer, SLOTracker


def test_metrics_counter_increment():
    m = Metrics()
    m.inc("requests")
    m.inc("requests", value=3)
    snap = m.snapshot()
    assert snap["counters"]["requests"] == 4


def test_metrics_counter_with_labels():
    m = Metrics()
    m.inc("http_requests", labels={"method": "GET", "status": "200"})
    m.inc("http_requests", labels={"method": "POST", "status": "201"})
    snap = m.snapshot()
    assert snap["counters"]["http_requests{method=GET,status=200}"] == 1
    assert snap["counters"]["http_requests{method=POST,status=201}"] == 1


def test_metrics_histogram():
    m = Metrics()
    for v in [10.0, 20.0, 30.0, 40.0, 50.0]:
        m.observe("latency_ms", v)
    snap = m.snapshot()
    h = snap["histograms"]["latency_ms"]
    assert h["count"] == 5
    assert h["min"] == 10.0
    assert h["max"] == 50.0
    assert h["avg"] == 30.0


def test_metrics_gauge():
    m = Metrics()
    m.gauge("queue_depth", 5.0)
    m.gauge("queue_depth", 12.0)
    snap = m.snapshot()
    assert snap["gauges"]["queue_depth"] == 12.0


def test_metrics_histogram_truncation():
    m = Metrics()
    for i in range(10005):
        m.observe("big", float(i))
    snap = m.snapshot()
    assert snap["histograms"]["big"]["count"] <= 5005


def test_span_lifecycle():
    s = Span("test_op")
    assert s.status == "ok"
    s.set_attribute("key", "value")
    s.finish()
    d = s.to_dict()
    assert d["name"] == "test_op"
    assert d["attributes"]["key"] == "value"
    assert d["duration_ms"] >= 0


def test_span_error():
    s = Span("failing")
    s.set_error("something broke")
    assert s.status == "error"
    assert s.to_dict()["attributes"]["error"] == "something broke"


def test_tracer_context_manager():
    t = Tracer()
    with t.span("test_span") as s:
        s.set_attribute("foo", "bar")
    spans = t.recent()
    assert len(spans) == 1
    assert spans[0]["name"] == "test_span"
    assert spans[0]["status"] == "ok"


def test_tracer_captures_error():
    t = Tracer()
    try:
        with t.span("bad") as s:
            raise ValueError("boom")
    except ValueError:
        pass
    spans = t.recent()
    assert len(spans) == 1
    assert spans[0]["status"] == "error"
    assert spans[0]["attributes"]["error"] == "boom"


def test_tracer_truncation():
    t = Tracer(max_spans=10)
    for i in range(15):
        with t.span(f"span_{i}"):
            pass
    spans = t.recent(limit=100)
    assert len(spans) <= 10


def test_slo_tracker_healthy():
    slo = SLOTracker()
    for _ in range(100):
        slo.record_request(is_error=False, scan_latency_ms=500.0)
    status = slo.status()
    assert status["slos"]["error_rate_pct"]["met"] is True
    assert status["slos"]["scan_latency_p95_ms"]["met"] is True
    assert status["total_requests"] == 100
    assert status["total_errors"] == 0


def test_slo_tracker_errors():
    slo = SLOTracker()
    for _ in range(50):
        slo.record_request(is_error=True)
    for _ in range(50):
        slo.record_request(is_error=False)
    status = slo.status()
    assert status["slos"]["error_rate_pct"]["met"] is False
    assert status["total_errors"] == 50


def test_slo_tracker_slow_latency():
    slo = SLOTracker()
    for i in range(30):
        slo.record_request(scan_latency_ms=6000.0)
    status = slo.status()
    assert status["slos"]["scan_latency_p95_ms"]["met"] is False
