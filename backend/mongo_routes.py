"""All-new endpoints powered exclusively by MongoDB Atlas.

These routes are Mongo-only. Each one demonstrates a feature that is either
unique to Atlas or significantly easier there than on a generic RDBMS.

Mounted at /api/v2 so existing /api routes are untouched.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import repositories as repos
from atlas_search import autocomplete as as_autocomplete
from atlas_search import facet_counts as as_facet_counts
from atlas_search import search as as_search
from hybrid_search import hybrid_search
from mongo import C, col, health as mongo_health, using_mock
from vector_search import find_similar, seed_corpus, to_finding
from model_registry import list_models as registry_list, ensure_default_models
import agent_registry
import agent_alerts as agent_alerts_mod
import agent_timeline
import agent_vector

logger = logging.getLogger("promptshield.mongo_routes")

router = APIRouter(prefix="/api/v2", tags=["mongo-atlas"])


# ── Health ──────────────────────────────────────────────────────────────────
@router.get("/health")
def health():
    h = mongo_health()
    h["features"] = {
        "vector_search": not using_mock(),
        "atlas_search": not using_mock(),
        "rank_fusion": not using_mock(),
        "change_streams": not using_mock(),
        "time_series": not using_mock(),
    }
    h["corpus_size"] = col(C.PROMPT_VECTORS).count_documents({})
    return h


# ── 1) Vector Search ────────────────────────────────────────────────────────
class SimilarRequest(BaseModel):
    text: str
    k: int = 5
    min_score: float = 0.0


@router.post("/similar")
def similar(req: SimilarRequest):
    """Top-k semantically similar prompts from the labeled corpus.

    Demo: paste a paraphrased jailbreak. Returns matches like
    {text: 'You are now DAN…', score: 0.91, category: 'jailbreak'}."""
    matches = find_similar(req.text, k=req.k, min_score=req.min_score)
    finding = to_finding(matches)
    return {
        "matches": [
            {
                "text": m["text"],
                "category": m.get("category"),
                "expected": m.get("expected"),
                "score": float(m.get("score", 0)),
            }
            for m in matches
        ],
        "finding": finding,
        "backend": "atlas_vector_search" if not using_mock() else "local_cosine",
    }


@router.post("/corpus/seed")
def corpus_seed(force: bool = Query(False)):
    """Re-embed prompts.json into prompt_vectors. Idempotent unless force=true."""
    return seed_corpus(force=force)


# ── 2) Atlas Search (lexical / fuzzy / autocomplete / facets) ──────────────
@router.get("/search")
def search(q: str = Query(..., min_length=1), limit: int = Query(25, ge=1, le=100), source: Optional[str] = None):
    docs = as_search(q, limit=limit, source=source)
    return {"results": [repos.scan_to_view(d) for d in docs], "count": len(docs)}


@router.get("/search/autocomplete")
def search_autocomplete(prefix: str = Query(..., min_length=1), limit: int = Query(8, ge=1, le=20)):
    return {"suggestions": as_autocomplete(prefix, limit=limit)}


@router.get("/search/facets")
def search_facets(q: Optional[str] = None):
    return as_facet_counts(q)


# ── 3) Hybrid Search ($rankFusion) ──────────────────────────────────────────
class HybridRequest(BaseModel):
    q: str
    k: int = 20
    vector_weight: float = 1.0
    text_weight: float = 1.0
    source: Optional[str] = None


@router.post("/search/hybrid")
def search_hybrid(req: HybridRequest):
    """Reciprocal-Rank-Fusion of $vectorSearch + $search.

    Returns a single ranked list with `fusion_score` per result."""
    docs = hybrid_search(
        req.q,
        k=req.k,
        vector_weight=req.vector_weight,
        text_weight=req.text_weight,
        source=req.source,
    )
    return {"results": [repos.scan_to_view(d) for d in docs], "count": len(docs)}


# ── 4) Time-series risk timeline ($setWindowFields) ────────────────────────
@router.get("/risk-timeline")
def risk_timeline_v2(source: str = Query("github"), days: int = Query(30, ge=7, le=180)):
    """Built on the time-series collection. Computes 7-day rolling avg in-DB."""
    rows = repos.snapshot_window(source=source, days=days)
    points = []
    for r in rows:
        ts = r.get("ts")
        points.append(
            {
                "ts": (ts or datetime.now(timezone.utc)).isoformat(),
                "risk_score": float(r.get("risk_score", 0)),
                "rolling_7d_avg": float(r.get("rolling_7d_avg", r.get("risk_score", 0))),
                "scan_count": int(r.get("scan_count", 0)),
                "critical": int(r.get("critical_count", 0)),
                "high": int(r.get("high_count", 0)),
            }
        )
    delta = 0.0
    if len(points) >= 2:
        delta = round(points[-1]["risk_score"] - points[0]["risk_score"], 2)
    return {"points": points, "trend_delta": delta}


# ── 5) Mongo-native scan reads ──────────────────────────────────────────────
@router.get("/scans")
def list_scans_v2(
    source: Optional[str] = None,
    repo: Optional[str] = None,
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    docs = repos.list_scans(source=source, repo=repo, limit=limit, offset=offset)
    return [repos.scan_to_view(d) for d in docs]


@router.get("/scans/{scan_id}")
def get_scan_v2(scan_id: str):
    doc = repos.get_scan(scan_id)
    if not doc:
        raise HTTPException(status_code=404, detail="scan not found")
    return repos.scan_to_view(doc)


@router.get("/scans/{scan_id}/similar")
def scan_similar(scan_id: str, k: int = Query(5, ge=1, le=20)):
    """Find historical scans semantically close to this one."""
    doc = repos.get_scan(scan_id)
    if not doc:
        raise HTTPException(status_code=404, detail="scan not found")
    matches = find_similar(doc.get("input_text", ""), k=k)
    return {
        "scan": repos.scan_to_view(doc),
        "matches": [
            {
                "text": m["text"],
                "category": m.get("category"),
                "expected": m.get("expected"),
                "score": float(m.get("score", 0)),
            }
            for m in matches
        ],
    }


# ── 6) Aggregations the SQL stack would have done with painful joins ───────
@router.get("/aggregations/repos")
def agg_repos(source: str = "github", limit: int = 10):
    rows = repos.repo_aggregates(source=source, limit=limit)
    return [
        {
            "repo_full_name": r["_id"],
            "scan_count": int(r["scan_count"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
            "max_risk": round(float(r["max_risk"]), 1),
        }
        for r in rows
    ]


@router.get("/aggregations/llm-targets")
def agg_targets():
    rows = repos.llm_target_distribution()
    return [{"target": r["_id"], "count": int(r["count"])} for r in rows]


@router.get("/aggregations/top-cwes")
def agg_top_cwes(days: int = Query(30, ge=1, le=365), limit: int = Query(10, ge=1, le=50)):
    rows = repos.top_cwes(days=days, limit=limit)
    return [{"cwe": r["_id"], "count": int(r["count"])} for r in rows]


# ── 7a) Agent Tool Registry (v0.5 — agentic-security pivot) ────────────────
@router.get("/agent-tools")
def list_agent_tools(
    repo: Optional[str] = Query(None, description="Filter to one repo_full_name"),
    risk_level: Optional[str] = Query(
        None, description="critical | high | medium | low"
    ),
    framework: Optional[str] = Query(
        None, description="langchain | mcp | openai | anthropic | crewai | …"
    ),
    capability: Optional[str] = Query(
        None, description="shell-exec | code-eval | sql-execute | filesystem-write | …"
    ),
    limit: int = Query(100, ge=1, le=500),
):
    """Catalog of AI-exposed tools observed across all scans.

    Each row is one (repo, tool_name) pair, with the worst-case capability
    set + missing safeguards we've ever seen. Powers the dashboard's "agent
    attack surface" view.
    """
    docs = agent_registry.list_agent_tools(
        repo_full_name=repo,
        risk_level=risk_level,
        framework=framework,
        capability=capability,
        limit=limit,
    )
    return {
        "tools": [agent_registry.agent_tool_to_view(d) for d in docs],
        "count": len(docs),
    }


@router.get("/agent-tools/aggregations/capabilities")
def agg_agent_capabilities(repo: Optional[str] = None):
    """Group-by capability — answers 'how much of our attack surface is shell?'"""
    return {"capabilities": agent_registry.capability_aggregates(repo_full_name=repo)}


@router.get("/agent-tools/aggregations/frameworks")
def agg_agent_frameworks():
    """Group-by framework — LangChain vs MCP vs OpenAI vs CrewAI exposure."""
    return {"frameworks": agent_registry.framework_aggregates()}


# ── 7b) Tool Risk Knowledge Base (Atlas Vector Search) ─────────────────────
class SimilarExploitRequest(BaseModel):
    tool_name: str
    capabilities: list[str] = []
    framework: Optional[str] = None
    evidence: Optional[str] = None
    k: int = 5


@router.post("/agent-tools/similar-exploits")
def similar_exploits(req: SimilarExploitRequest):
    """Atlas $vectorSearch over a curated knowledge base of dangerous tool
    patterns. Given a tool's metadata, return the top-k semantically similar
    historical exploits (with CVE / blog refs). Falls back to local cosine
    on mongomock or before the index is provisioned."""
    matches = agent_vector.find_similar_exploits(
        tool_name=req.tool_name,
        capabilities=req.capabilities,
        framework=req.framework,
        evidence=req.evidence,
        k=req.k,
    )
    return {
        "matches": matches,
        "backend": "atlas_vector_search" if not using_mock() else "local_cosine",
    }


@router.post("/agent-tools/exploit-corpus/seed")
def seed_exploit_corpus(force: bool = Query(False)):
    """Embed and upsert the curated exploit corpus. Idempotent unless force=true."""
    return agent_vector.seed_exploit_corpus(force=force)


# ── 7c) Critical-finding alerts (Atlas Trigger + Python fallback) ──────────
@router.get("/agent-alerts")
def list_agent_alerts(
    repo: Optional[str] = None,
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """Recent critical agentic findings, written either by the Atlas Trigger
    (when configured) or by the Python pipeline as a degraded-mode fallback."""
    docs = agent_alerts_mod.list_alerts(
        repo_full_name=repo, acknowledged=acknowledged, limit=limit
    )
    return {
        "alerts": [agent_alerts_mod.alert_to_view(d) for d in docs],
        "count": len(docs),
        "trigger_status": agent_alerts_mod.trigger_status(),
    }


@router.post("/agent-alerts/{alert_id}/acknowledge")
def acknowledge_agent_alert(alert_id: str, by: str = Query("anonymous")):
    ok = agent_alerts_mod.acknowledge(alert_id, by=by)
    if not ok:
        raise HTTPException(status_code=404, detail="alert not found")
    return {"ok": True, "alert_id": alert_id, "acknowledged_by": by}


# ── 7d) Agent surface timeline (Atlas time-series) ─────────────────────────
@router.get("/agent-surface-timeline")
def agent_surface_timeline(
    repo: Optional[str] = None,
    days: int = Query(30, ge=1, le=180),
):
    """Time-series of agent attack-surface size per scan. Backed by an Atlas
    time-series collection in production; a regular collection on mongomock."""
    return agent_timeline.timeline_window(repo_full_name=repo, days=days)


# ── 7e) Hybrid $rankFusion search over the tool registry ───────────────────
class AgentToolSearchRequest(BaseModel):
    q: str
    k: int = 20
    vector_weight: float = 1.0
    text_weight: float = 1.0


@router.post("/agent-tools/search")
def search_agent_tools(req: AgentToolSearchRequest):
    """Reciprocal-Rank-Fusion of $vectorSearch + $search over agent_tools.

    Useful for queries like 'tools that touch the filesystem with no
    allowlist' — the vector pipeline catches the *meaning*, the text pipeline
    catches literal `tool_name` matches like `delete_file`.
    """
    docs = hybrid_search(
        req.q,
        k=req.k,
        vector_weight=req.vector_weight,
        text_weight=req.text_weight,
        collection=C.AGENT_TOOLS,
        vector_index="agent_tools_vector_idx",
        text_index="agent_tools_text_idx",
        text_paths=["tool_name", "evidence_samples", "framework", "capabilities"],
        embedding_text=req.q,
    )
    out = []
    for d in docs:
        view = agent_registry.agent_tool_to_view(d)
        if "fusion_score" in d:
            try:
                view["fusion_score"] = float(d["fusion_score"]) if isinstance(
                    d["fusion_score"], (int, float)
                ) else d["fusion_score"]
            except Exception:
                view["fusion_score"] = d["fusion_score"]
        out.append(view)
    return {"results": out, "count": len(out)}


# ── 8) Benchmark / model registry (writes to BENCHMARK_RUNS) ───────────────
class BenchmarkRunPayload(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion_matrix: dict[str, int]
    sample_count: int
    layers_enabled: list[str] = []
    notes: Optional[str] = None


@router.post("/benchmark/runs")
def post_benchmark_run(payload: BenchmarkRunPayload):
    return {"id": str(repos.insert_benchmark_run(payload.model_dump())["_id"])}


# ── 8) GridFS-backed model registry (artifact + version listing) ───────────
@router.get("/models")
def list_registered_models(name: Optional[str] = None):
    """Versions of every model artifact stored in GridFS (`model_registry` bucket)."""
    return {"models": registry_list(name=name)}


@router.post("/models/bootstrap")
def bootstrap_models():
    """Idempotent: ensure ml_classifier.pkl is in GridFS. Returns the action taken."""
    return ensure_default_models()


@router.get("/benchmark/runs")
def list_benchmark_runs(limit: int = Query(20, ge=1, le=100)):
    rows = repos.recent_benchmark_runs(limit=limit)
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r.get("_id")),
                "ts": (r.get("ts") or datetime.now(timezone.utc)).isoformat(),
                "accuracy": float(r.get("accuracy", 0)),
                "precision": float(r.get("precision", 0)),
                "recall": float(r.get("recall", 0)),
                "f1": float(r.get("f1", 0)),
                "sample_count": int(r.get("sample_count", 0)),
                "confusion_matrix": r.get("confusion_matrix", {}),
                "layers_enabled": r.get("layers_enabled", []),
                "notes": r.get("notes"),
            }
        )
    return out
