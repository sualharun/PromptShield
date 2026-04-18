import time
from collections import deque
from threading import Lock
from typing import Deque, Dict


class SlidingWindowLimiter:
    """In-memory per-key sliding window. Suitable for single-process deployments."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry = max(1, int(self.window - (now - bucket[0])))
                return False, 0, retry
            bucket.append(now)
            return True, self.max_requests - len(bucket), 0
