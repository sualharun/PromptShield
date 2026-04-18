"""Dependency risk graph API endpoints.

POST /api/graph/analyze/{scan_id} — run full dependency graph analysis
GET  /api/graph/{scan_id}         — fetch cached graph data
POST /api/graph/analyze-text      — analyze raw dependency file contents
"""

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import (
    Dependency,
    FindingDependency,
    GraphEdge as GraphEdgeRow,
    GraphNode as GraphNodeRow,
    Maintainer,
    Scan,
    VulnerableRepo,
    get_db,
)
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


class DependencyNode(BaseModel):
    id: str
    name: str
    type: str
    risk_score: float
    version: Optional[str] = None
    vulnerabilities: Optional[list] = None
    ecosystem: Optional[str] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    risk: str


class BlastRadius(BaseModel):
    affected_count: int
    affected_packages: List[str]
    description: str


class GraphResponse(BaseModel):
    nodes: List[dict]
    edges: List[dict]
    overall_risk_score: float
    threat_level: str
    blast_radius: dict
    narrative: str
    risk_chains: List[dict] = []
    insights: dict = {}
    scan_id: Optional[int] = None


@router.post("/analyze/{scan_id}", response_model=GraphResponse)
def analyze_scan_graph(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    text = scan.input_text or ""
    language = _detect_dep_language(text)
    deps = extract_dependencies(text, language)

    if not deps:
        deps = _extract_deps_from_findings(scan)

    author = scan.author_login or "unknown"
    context = {
        "scan_id": scan.id,
        "repo_full_name": scan.repo_full_name,
        "pr_number": scan.pr_number,
        "commit_sha": scan.commit_sha,
    }
    graph_data = build_risk_graph(
        deps,
        author,
        fetch_vulns=True,
        context=context,
        maintainers=_load_maintainers(db),
        vulnerable_repos=_load_vulnerable_repos(db),
    )
    narrative = generate_risk_narrative(graph_data)

    _persist_graph(db, scan, graph_data, narrative, deps)

    return GraphResponse(
        nodes=graph_data["nodes"],
        edges=graph_data["edges"],
        overall_risk_score=graph_data["overall_risk_score"],
        threat_level=graph_data["threat_level"],
        blast_radius=graph_data["blast_radius"],
        narrative=narrative,
        risk_chains=graph_data.get("risk_chains", []),
        insights=graph_data.get("insights", {}),
        scan_id=scan_id,
    )


@router.get("/{scan_id}", response_model=GraphResponse)
def get_graph(scan_id: int, db: Session = Depends(get_db)):
    data = _load_scan_graph(scan_id, db)

    return GraphResponse(
        nodes=data.get("nodes", []),
        edges=data.get("edges", []),
        overall_risk_score=data.get("overall_risk_score", 0),
        threat_level=data.get("threat_level", "LOW"),
        blast_radius=data.get("blast_radius", {"affected_count": 0, "affected_packages": [], "description": ""}),
        narrative=data.get("narrative", ""),
        risk_chains=data.get("risk_chains", []),
        insights=data.get("insights", {}),
        scan_id=scan_id,
    )


@router.get("/{scan_id}/blast-radius")
def get_blast_radius(scan_id: int, db: Session = Depends(get_db)):
    data = _load_scan_graph(scan_id, db)
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
def get_narrative(scan_id: int, db: Session = Depends(get_db)):
    data = _load_scan_graph(scan_id, db)
    return {
        "scan_id": scan_id,
        "threat_level": data.get("threat_level", "LOW"),
        "overall_risk_score": data.get("overall_risk_score", 0),
        "plain_english_explanation": data.get("narrative", ""),
    }


@router.get("/{scan_id}/paths")
def get_risk_paths(scan_id: int, db: Session = Depends(get_db)):
    data = _load_scan_graph(scan_id, db)
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
        context={"scan_id": "adhoc", "repo_full_name": "adhoc/local", "pr_number": "n/a"},
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


def _detect_dep_language(text: str) -> str:
    if "require(" in text or '"dependencies"' in text or "from 'react'" in text:
        return "node"
    return "python"


def _extract_deps_from_findings(scan: Scan) -> List[dict]:
    """Extract dependency info from existing VULNERABLE_DEPENDENCY findings."""
    findings = json.loads(scan.findings_json or "[]")
    deps = []
    seen = set()
    for f in findings:
        if f.get("type") != "VULNERABLE_DEPENDENCY":
            continue
        evidence = f.get("evidence", "")
        parts = evidence.split("==")
        if len(parts) >= 2:
            name = parts[0].strip()
            version = parts[1].split("(")[0].strip()
        else:
            name = f.get("title", "").split("@")[0].split(":")[0].strip()
            version = "unknown"
        if name and name not in seen:
            seen.add(name)
            deps.append({
                "name": name.lower(),
                "version": version,
                "direct": True,
                "transitive": [],
                "ecosystem": "python",
            })
    return deps


def _persist_graph(
    db: Session,
    scan: Scan,
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
    scan.graph_analysis_json = json.dumps(analysis)

    db.query(GraphNodeRow).filter(GraphNodeRow.scan_id == scan.id).delete()
    db.query(GraphEdgeRow).filter(GraphEdgeRow.scan_id == scan.id).delete()

    for node in graph_data["nodes"]:
        db.add(
            GraphNodeRow(
                scan_id=scan.id,
                node_id=node.get("id"),
                node_type=node.get("type", "unknown"),
                name=node.get("name", node.get("id", "unknown")),
                risk_score=float(node.get("risk_score", 0)),
                props_json=json.dumps(node),
            )
        )

    for edge in graph_data["edges"]:
        db.add(
            GraphEdgeRow(
                scan_id=scan.id,
                source_node_id=edge.get("source"),
                target_node_id=edge.get("target"),
                edge_type=edge.get("type", "linked_to"),
                risk=edge.get("risk", "low"),
                props_json=json.dumps(edge),
            )
        )

    for dep_info in deps:
        dep_nodes = [n for n in graph_data["nodes"] if n.get("name") == dep_info["name"] and n["type"] == "dependency"]
        risk = dep_nodes[0]["risk_score"] if dep_nodes else 0
        cve_count = len(dep_nodes[0].get("vulnerabilities", [])) if dep_nodes else 0

        existing = db.query(Dependency).filter(
            Dependency.name == dep_info["name"],
            Dependency.version == dep_info["version"],
        ).first()

        if existing:
            existing.risk_score = risk
            existing.cve_count = cve_count
            dep_id = existing.id
        else:
            dep_row = Dependency(
                name=dep_info["name"],
                version=dep_info["version"],
                registry="pypi" if dep_info["ecosystem"] == "python" else "npm",
                ecosystem=dep_info["ecosystem"],
                risk_score=risk,
                cve_count=cve_count,
            )
            db.add(dep_row)
            db.flush()
            dep_id = dep_row.id

        db.add(FindingDependency(scan_id=scan.id, dependency_id=dep_id))

    db.commit()


def _load_scan_graph(scan_id: int, db: Session) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.graph_analysis_json:
        raise HTTPException(
            status_code=404,
            detail="No graph analysis available. Run POST /api/graph/analyze/{scan_id} first.",
        )

    try:
        return json.loads(scan.graph_analysis_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=500, detail="Corrupt graph data")


def _load_maintainers(db: Session) -> List[dict]:
    rows = db.query(Maintainer).all()
    out = []
    for r in rows:
        try:
            repos = json.loads(r.repositories_json or "[]")
        except Exception:
            repos = []
        out.append(
            {
                "name": r.name,
                "repositories": repos,
                "risk_level": r.risk_level,
                "exploit_history": r.exploit_history,
            }
        )
    return out


def _load_vulnerable_repos(db: Session) -> List[dict]:
    rows = db.query(VulnerableRepo).all()
    out = []
    for r in rows:
        try:
            cve_ids = json.loads(r.cve_ids_json or "[]")
        except Exception:
            cve_ids = []
        out.append(
            {
                "name": r.name,
                "cve_ids": cve_ids,
                "severity": r.severity,
                "description": r.description,
                "remediation": r.remediation,
            }
        )
    return out
