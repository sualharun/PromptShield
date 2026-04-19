"""Shared orchestration for /api/scan, PR file scans, and async jobs."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

from config import settings
from dataflow import scan_dataflow
from ai_analyzer import ai_scan
from scanner import static_scan


def parallel_core_scan(text: str, detected_language: str) -> Tuple[List[dict], List[dict], List[dict]]:
    """Run static + dataflow always; optional Vertex/Gemini when not in fast mode."""
    if settings.PROMPTSHIELD_SCAN_MODE == "fast":
        with ThreadPoolExecutor(max_workers=2) as pool:
            static_future = pool.submit(static_scan, text, detected_language)
            dataflow_future = pool.submit(scan_dataflow, text)
            static_results = static_future.result()
            dataflow_results = dataflow_future.result()
        return static_results, [], dataflow_results

    with ThreadPoolExecutor(max_workers=3) as pool:
        static_future = pool.submit(static_scan, text, detected_language)
        ai_future = pool.submit(ai_scan, text)
        dataflow_future = pool.submit(scan_dataflow, text)
        static_results = static_future.result()
        ai_results = ai_future.result()
        dataflow_results = dataflow_future.result()
    return static_results, ai_results, dataflow_results
