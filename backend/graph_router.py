"""Dependency risk graph API endpoints.

POST /api/graph/analyze/{scan_id} — run full dependency graph analysis
GET  /api/graph/{scan_id}         — fetch cached graph data
POST /api/graph/analyze-text      — analyze raw dependency file contents

v0.4: Mongo-backed. Graph analysis is persisted on the scan document under
`graph_analysis`, with mirror copies in `graph_nodes` / `graph_edges` /
`dependencies` for ad-hoc Atlas queries and Charts.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import repositories as repos
from mongo import C, col
from risk_graph import (
    build_risk_graph,
    extract_dependencies,
    generate_risk_narrative,
)

logger = logging.getLogger("promptshield.graph")
router = APIRouter(prefix="/api/graph", tags=["graph"])


class AnalyzeTextRequest(BaseModel):
    content: str
    language: str = "python"
    author: str = "unknown"
    fetch_vulns: bool = True


class GraphResponse(BaseModel):
    nodes: List[dict]
    edges: List[dict]
    overall_risk_score: float
    threat_level: str
    blast_radius: dict
    narrative: str
    risk_chains: List[dict] = []
    insights: dict = {}
    scan_id: Optional[str] = None


# ── routes ─────────────────────────────────────────────────────────────────
@router.post("/analyze/{scan_id}", response_model=GraphResponse)
def analyze_scan_graph(scan_id: str):
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    text = scan.get("input_text") or ""
    language = _detect_dep_language(text)
    deps = extract_dependencies(text, language)
    if not deps:
        deps = _extract_deps_from_findings(scan)

    gh = scan.get("github") or {}
    author = gh.get("author_login") or "unknown"
    sid = str(scan.get("_id"))
    context = {
        "scan_id": sid,
        "repo_full_name": gh.get("repo_full_name"),
        "pr_number": gh.get("pr_number"),
        "commit_sha": gh.get("commit_sha"),
    }
    graph_data = build_risk_graph(
        deps,
        author,
        fetch_vulns=True,
        context=context,
        maintainers=[],
        vulnerable_repos=[],
    )
    narrative = generate_risk_narrative(graph_data)

    _persist_graph(sid, graph_data, narrative, deps)

    return GraphResponse(
        nodes=graph_data["nodes"],
        edges=graph_data["edges"],
        overall_risk_score=graph_data["overall_risk_score"],
        threat_level=graph_data["threat_level"],
        blast_radius=graph_data["blast_radius"],
        narrative=narrative,
        risk_chains=graph_data.get("risk_chains", []),
        insights=graph_data.get("insights", {}),
        scan_id=sid,
    )


@router.get("/{scan_id}", response_model=GraphResponse)
def get_graph(scan_id: str):
    data = _load_scan_graph(scan_id)
    return GraphResponse(
        nodes=data.get("nodes", []),
        edges=data.get("edges", []),
        overall_risk_score=data.get("overall_risk_score", 0),
        threat_level=data.get("threat_level", "LOW"),
        blast_radius=data.get(
            "blast_radius",
            {"affected_count": 0, "affected_packages": [], "description": ""},
        ),
        narrative=data.get("narrative", ""),
        risk_chains=data.get("risk_chains", []),
        insights=data.get("insights", {}),
        scan_id=scan_id,
    )


@router.get("/{scan_id}/blast-radius")
def get_blast_radius(scan_id: str):
    data = _load_scan_graph(scan_id)
    return {
        "scan_id": scan_id,
        "threat_level": data.get("threat_level", "LOW"),
        "overall_risk_score": data.get("overall_risk_score", 0),
        "blast_radius": data.get(
            "blast_radius",
            {"affected_count": 0, "affected_packages": [], "description": ""},
        ),
    }


@router.get("/{scan_id}/narrative")
def get_narrative(scan_id: str):
    data = _load_scan_graph(scan_id)
    return {
        "scan_id": scan_id,
        "threat_level": data.get("threat_level", "LOW"),
        "overall_risk_score": data.get("overall_risk_score", 0),
        "plain_english_explanation": data.get("narrative", ""),
    }


@router.get("/{scan_id}/paths")
def get_risk_paths(scan_id: str):
    data = _load_scan_graph(scan_id)
    return {
        "scan_id": scan_id,
        "risk_chains": data.get("risk_chains", []),
        "insights": data.get("insights", {}),
    }


@router.post("/analyze-text", response_model=GraphResponse)
def analyze_text_graph(req: AnalyzeTextRequest):
    deps = extract_dependencies(req.content, req.language)
    graph_data = build_risk_graph(
        deps,
        req.author,
        fetch_vulns=req.fetch_vulns,
        context={
            "scan_id": "adhoc",
            "repo_full_name": "adhoc/local",
            "pr_number": "n/a",
        },
        maintainers=[],
        vulnerable_repos=[],
    )
    narrative = generate_risk_narrative(graph_data)
    return GraphResponse(
        nodes=graph_data["nodes"],
        edges=graph_data["edges"],
        overall_risk_score=graph_data["overall_risk_score"],
        threat_level=graph_data["threat_level"],
        blast_radius=graph_data["blast_radius"],
        narrative=narrative,
        risk_chains=graph_data.get("risk_chains", []),
        insights=graph_data.get("insights", {}),
    )


# ── helpers ────────────────────────────────────────────────────────────────
def _detect_dep_language(text: str) -> str:
    if "require(" in text or '"dependencies"' in text or "from 'react'" in text:
        return "node"
    return "python"


def _extract_deps_from_findings(scan: dict) -> List[dict]:
    findings = list(scan.get("findings") or [])
    deps: list[dict] = []
    seen: set[str] = set()
    for f in findings:
        if f.get("type") != "VULNERABLE_DEPENDENCY":
            continue
        evidence = str(f.get("evidence", ""))
        parts = evidence.split("==")
        if len(parts) >= 2:
            name = parts[0].strip()
            version = parts[1].split("(")[0].strip()
        else:
            name = str(f.get("title", "")).split("@")[0].split(":")[0].strip()
            version = "unknown"
        if name and name not in seen:
            seen.add(name)
            deps.append(
                {
                    "name": name.lower(),
                    "version": version,
                    "direct": True,
                    "transitive": [],
                    "ecosystem": "python",
                }
            )
    return deps


def _persist_graph(
    scan_id: str,
    graph_data: dict,
    narrative: str,
    deps: list,
) -> None:
    analysis = {
        "nodes": graph_data["nodes"],
        "edges": graph_data["edges"],
        "overall_risk_score": graph_data["overall_risk_score"],
        "threat_level": graph_data["threat_level"],
        "blast_radius": graph_data["blast_radius"],
        "narrative": narrative,
        "risk_chains": graph_data.get("risk_chains", []),
        "insights": graph_data.get("insights", {}),
    }
    repos.update_scan(scan_id, {"graph_analysis": analysis})

    col(C.GRAPH_NODES).delete_many({"scan_id": scan_id})
    col(C.GRAPH_EDGES).delete_many({"scan_id": scan_id})

    if graph_data["nodes"]:
        col(C.GRAPH_NODES).insert_many(
            [
                {
                    "scan_id": scan_id,
                    "node_id": n.get("id"),
                    "node_type": n.get("type", "unknown"),
                    "name": n.get("name", n.get("id", "unknown")),
                    "risk_score": float(n.get("risk_score", 0)),
                    "props": n,
                }
                for n in graph_data["nodes"]
            ]
        )
    if graph_data["edges"]:
        col(C.GRAPH_EDGES).insert_many(
            [
                {
                    "scan_id": scan_id,
                    "source_node_id": e.get("source"),
                    "target_node_id": e.get("target"),
                    "edge_type": e.get("type", "linked_to"),
                    "risk": e.get("risk", "low"),
                    "props": e,
                }
                for e in graph_data["edges"]
            ]
        )

    for dep_info in deps:
        dep_nodes = [
            n
            for n in graph_data["nodes"]
            if n.get("name") == dep_info["name"] and n.get("type") == "dependency"
        ]
        risk = float(dep_nodes[0]["risk_score"]) if dep_nodes else 0.0
        cve_count = len(dep_nodes[0].get("vulnerabilities", [])) if dep_nodes else 0

        col(C.DEPENDENCIES).update_one(
            {"name": dep_info["name"], "version": dep_info["version"]},
            {
                "$set": {
                    "registry": "pypi" if dep_info.get("ecosystem") == "python" else "npm",
                    "ecosystem": dep_info.get("ecosystem"),
                    "risk_score": risk,
                    "cve_count": cve_count,
                },
                "$addToSet": {"scan_ids": scan_id},
            },
            upsert=True,
        )


def _load_scan_graph(scan_id: str) -> dict:
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    analysis = scan.get("graph_analysis")
    if not analysis:
        raise HTTPException(
            status_code=404,
            detail="No graph analysis available. Run POST /api/graph/analyze/{scan_id} first.",
        )
    if isinstance(analysis, str):
        try:
            import json as _json

            return _json.loads(analysis)
        except Exception:
            raise HTTPException(status_code=500, detail="Corrupt graph data")
    return analysis
