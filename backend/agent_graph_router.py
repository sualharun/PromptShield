"""Agent Attack Surface graph API endpoints.

POST /api/agent-graph/analyze/{scan_id} — build agent attack surface graph
GET  /api/agent-graph/{scan_id}         — fetch cached agent graph data
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import repositories as repos
from agent_graph import build_agent_graph

logger = logging.getLogger("promptshield.agent_graph")
router = APIRouter(prefix="/api/agent-graph", tags=["agent-graph"])


class AgentGraphResponse(BaseModel):
    nodes: List[dict]
    edges: List[dict]
    overall_risk_score: float
    threat_level: str
    blast_radius: dict
    risk_chains: List[dict] = []
    insights: dict = {}
    scan_id: Optional[str] = None


@router.post("/analyze/{scan_id}", response_model=AgentGraphResponse)
def analyze_agent_graph(scan_id: str):
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    text = scan.get("input_text") or ""
    findings = list(scan.get("findings") or [])
    gh = scan.get("github") or {}
    sid = str(scan.get("_id"))

    graph_data = build_agent_graph(
        findings,
        code=text,
        scan_context={
            "scan_id": sid,
            "agent_name": gh.get("repo_full_name") or "AI Agent",
            "repo_full_name": gh.get("repo_full_name"),
            "pr_number": gh.get("pr_number"),
        },
    )

    # Persist on the scan document
    repos.update_scan(sid, {"agent_graph_analysis": graph_data})

    return AgentGraphResponse(
        nodes=graph_data["nodes"],
        edges=graph_data["edges"],
        overall_risk_score=graph_data["overall_risk_score"],
        threat_level=graph_data["threat_level"],
        blast_radius=graph_data["blast_radius"],
        risk_chains=graph_data.get("risk_chains", []),
        insights=graph_data.get("insights", {}),
        scan_id=sid,
    )


@router.get("/{scan_id}", response_model=AgentGraphResponse)
def get_agent_graph(scan_id: str):
    scan = repos.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = scan.get("agent_graph_analysis")
    if not data:
        raise HTTPException(
            status_code=404,
            detail="No agent graph analysis available. Run POST /api/agent-graph/analyze/{scan_id} first.",
        )

    if isinstance(data, str):
        try:
            import json
            data = json.loads(data)
        except Exception:
            raise HTTPException(status_code=500, detail="Corrupt agent graph data")

    return AgentGraphResponse(
        nodes=data.get("nodes", []),
        edges=data.get("edges", []),
        overall_risk_score=data.get("overall_risk_score", 0),
        threat_level=data.get("threat_level", "LOW"),
        blast_radius=data.get(
            "blast_radius",
            {"affected_count": 0, "affected_packages": [], "description": ""},
        ),
        risk_chains=data.get("risk_chains", []),
        insights=data.get("insights", {}),
        scan_id=scan_id,
    )
