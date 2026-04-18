"""Observability: metrics, tracing spans, and SLO tracking.

Provides in-process metrics collection and span tracking without requiring
an external collector. When OTEL_EXPORTER_OTLP_ENDPOINT is set, traces
are exported; otherwise metrics are queryable via /api/ops/metrics.
"""

import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from contextlib import contextmanager


class Metrics:
    """Thread-safe in-process metrics collector."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._gauges: Dict[str, float] = {}

    def inc(self, name: str, value: int = 1, labels: Optional[Dict] = None):
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += value

    def observe(self, name: str, value: float, labels: Optional[Dict] = None):
        key = self._key(name, labels)
        with self._lock:
            hist = self._histograms[key]
            hist.append(value)
            if len(hist) > 10000:
                hist[:] = hist[-5000:]

    def gauge(self, name: str, value: float, labels: Optional[Dict] = None):
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            hist_stats = {}
            for k, values in self._histograms.items():
                if not values:
                    continue
                sorted_v = sorted(values)
                n = len(sorted_v)
                hist_stats[k] = {
                    "count": n,
                    "min": sorted_v[0],
                    "max": sorted_v[-1],
                    "avg": sum(sorted_v) / n,
                    "p50": sorted_v[int(n * 0.5)],
                    "p95": sorted_v[int(n * 0.95)] if n >= 20 else sorted_v[-1],
                    "p99": sorted_v[int(n * 0.99)] if n >= 100 else sorted_v[-1],
                }
            return {
                "counters": dict(self._counters),
                "histograms": hist_stats,
                "gauges": dict(self._gauges),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }

    def _key(self, name: str, labels: Optional[Dict] = None) -> str:
        if not labels:
            return name
        parts = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{parts}}}"


class Span:
    """Lightweight tracing span."""

    def __init__(self, name: str, parent_id: Optional[str] = None):
        self.name = name
        self.span_id = f"{time.monotonic_ns():x}"[:12]
        self.parent_id = parent_id
        self.start_time = time.monotonic()
        self.end_time: Optional[float] = None
        self.attributes: Dict[str, Any] = {}
        self.status = "ok"

    def set_attribute(self, key: str, value: Any):
        self.attributes[key] = value

    def set_error(self, error: str):
        self.status = "error"
        self.attributes["error"] = error

    def finish(self):
        self.end_time = time.monotonic()

    @property
    def duration_ms(self) -> float:
        end = self.end_time or time.monotonic()
        return (end - self.start_time) * 1000

    def to_dict(self) -> Dict:
        return {
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "duration_ms": round(self.duration_ms, 2),
            "status": self.status,
            "attributes": self.attributes,
        }


class Tracer:
    """In-process trace collector. Keeps recent spans for the /api/ops/traces endpoint."""

    def __init__(self, max_spans: int = 500):
        self._lock = threading.Lock()
        self._spans: List[Dict] = []
        self._max = max_spans

    @contextmanager
    def span(self, name: str, parent_id: Optional[str] = None):
        s = Span(name, parent_id)
        try:
            yield s
        except Exception as e:
            s.set_error(str(e))
            raise
        finally:
            s.finish()
            with self._lock:
                self._spans.append(s.to_dict())
                if len(self._spans) > self._max:
                    self._spans[:] = self._spans[-self._max // 2:]

    def recent(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            return list(self._spans[-limit:])


class SLOTracker:
    """Tracks SLO compliance: latency targets and error budgets."""

    def __init__(self):
        self._lock = threading.Lock()
        self._targets: Dict[str, Dict] = {
            "scan_latency_p95_ms": {"target": 5000, "window_seconds": 3600},
            "error_rate_pct": {"target": 1.0, "window_seconds": 3600},
            "availability_pct": {"target": 99.5, "window_seconds": 86400},
        }
        self._request_count = 0
        self._error_count = 0
        self._scan_latencies: List[float] = []

    def record_request(self, is_error: bool = False, scan_latency_ms: Optional[float] = None):
        with self._lock:
            self._request_count += 1
            if is_error:
                self._error_count += 1
            if scan_latency_ms is not None:
                self._scan_latencies.append(scan_latency_ms)
                if len(self._scan_latencies) > 10000:
                    self._scan_latencies[:] = self._scan_latencies[-5000:]

    def status(self) -> Dict:
        with self._lock:
            total = max(1, self._request_count)
            error_rate = (self._error_count / total) * 100
            latencies = sorted(self._scan_latencies) if self._scan_latencies else [0]
            p95 = latencies[int(len(latencies) * 0.95)] if len(latencies) >= 20 else (latencies[-1] if latencies else 0)
            return {
                "slos": {
                    "scan_latency_p95_ms": {
                        "target": 5000,
                        "current": round(p95, 1),
                        "met": p95 <= 5000,
                    },
                    "error_rate_pct": {
                        "target": 1.0,
                        "current": round(error_rate, 2),
                        "met": error_rate <= 1.0,
                    },
                },
                "total_requests": self._request_count,
                "total_errors": self._error_count,
                "total_scans_tracked": len(self._scan_latencies),
            }


metrics = Metrics()
tracer = Tracer()
slo_tracker = SLOTracker()
