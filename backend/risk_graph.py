"""Dependency risk graph engine with multi-hop propagation.

Models contributor, commit, repo, dependency, maintainer, and vulnerable-repo nodes
to explain hidden supply-chain risk paths in PRs.
"""

import json
import logging
import os
import re
from collections import defaultdict, deque
from typing import Dict, List

from config import settings

logger = logging.getLogger("promptshield.risk_graph")

SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
RISK_LEVEL_WEIGHT = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}


def extract_dependencies(source: str, language: str = "python") -> List[Dict]:
    """Extract dependencies from a repo path or from raw dependency file contents."""
    content = source or ""
    if os.path.isdir(content):
        content = _read_dependency_file(content, language)

    if language == "python":
        return _parse_requirements(content)
    elif language == "node":
        return _parse_package_json(content)
    return []


def _read_dependency_file(repo_path: str, language: str) -> str:
    """Read dependency file text from repository root for MVP extraction."""
    if language == "python":
        candidate = os.path.join(repo_path, "requirements.txt")
    else:
        candidate = os.path.join(repo_path, "package.json")

    if not os.path.exists(candidate):
        return ""
    try:
        with open(candidate, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _parse_requirements(content: str) -> List[Dict]:
    deps = []
    for raw in (content or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[><=!~\[]", line, maxsplit=1)[0].strip()
        if not name:
            continue
        version = "unknown"
        m = re.search(r"==\s*([0-9A-Za-z.\-+]+)", line)
        if m:
            version = m.group(1)
        deps.append({
            "name": name.lower(),
            "version": version,
            "direct": True,
            "transitive": [],
            "ecosystem": "python",
        })
    return deps


def _parse_package_json(content: str) -> List[Dict]:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            version = re.sub(r"[\^~>=<\s]", "", spec) or "unknown"
            deps.append({
                "name": name.lower(),
                "version": version,
                "direct": True,
                "transitive": [],
                "ecosystem": "node",
            })
    return deps


def fetch_vulnerabilities(dep_name: str, ecosystem: str) -> List[Dict]:
    """Fetch known CVEs from osv.dev. Returns empty list on failure."""
    try:
        import httpx
    except ImportError:
        logger.warning("httpx library not available for vuln lookup")
        return []

    osv_ecosystem = "PyPI" if ecosystem == "python" else "npm"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"ecosystem": osv_ecosystem, "name": dep_name}},
            )
        if resp.status_code != 200:
            return []

        vulns = []
        for v in resp.json().get("vulns", []):
            severity = _extract_severity(v)
            refs = v.get("references", [])
            vulns.append({
                "cve_id": v.get("id", "UNKNOWN"),
                "severity": severity,
                "description": v.get("summary", ""),
                "advisory_url": refs[0].get("url", "") if refs else "",
            })
        return vulns
    except Exception as e:
        logger.warning("vuln fetch failed for %s: %s", dep_name, e)
        return []


def _extract_severity(vuln: Dict) -> str:
    """Extract severity from OSV vuln entry."""
    for db_specific in vuln.get("database_specific", {}).get("severity", []):
        if isinstance(db_specific, str):
            return db_specific.upper()

    severity_entries = vuln.get("severity", [])
    for entry in severity_entries:
        score_str = entry.get("score", "")
        if score_str:
            try:
                score = float(score_str)
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"
            except (ValueError, TypeError):
                pass

    summary = (vuln.get("summary") or "").lower()
    if "critical" in summary:
        return "CRITICAL"
    if "high" in summary or "remote code" in summary:
        return "HIGH"
    if "low" in summary:
        return "LOW"
    return "MEDIUM"


def build_risk_graph(
    dependencies: List[Dict],
    pr_author: str,
    fetch_vulns: bool = True,
    context: Dict | None = None,
    maintainers: List[Dict] | None = None,
    vulnerable_repos: List[Dict] | None = None,
) -> Dict:
    """Build a multi-hop risk graph and propagate risk to PR-level entities."""
    context = context or {}
    maintainers = maintainers or []
    vulnerable_repos = vulnerable_repos or []

    nodes_by_id: Dict[str, Dict] = {}
    edges: List[Dict] = []

    pr_node = _upsert_node(
        nodes_by_id,
        f"pr:{context.get('scan_id', 'unknown')}",
        {
            "name": f"PR #{context.get('pr_number', 'n/a')}",
            "type": "pull_request",
            "risk_score": 0,
        },
    )
    contributor_node = _upsert_node(
        nodes_by_id,
        f"user:{pr_author or 'unknown'}",
        {"name": pr_author or "unknown", "type": "contributor", "risk_score": 5},
    )
    _add_edge(edges, pr_node["id"], contributor_node["id"], "authored_by", "low")

    if context.get("repo_full_name"):
        repo_node = _upsert_node(
            nodes_by_id,
            f"repo:{context['repo_full_name']}",
            {
                "name": context["repo_full_name"],
                "type": "repository",
                "risk_score": 10,
            },
        )
        _add_edge(edges, pr_node["id"], repo_node["id"], "targets_repo", "low")
    else:
        repo_node = None

    if context.get("commit_sha"):
        commit_node = _upsert_node(
            nodes_by_id,
            f"commit:{context['commit_sha']}",
            {
                "name": context["commit_sha"][:10],
                "type": "commit",
                "risk_score": 10,
            },
        )
        _add_edge(edges, pr_node["id"], commit_node["id"], "contains_commit", "low")
        _add_edge(edges, commit_node["id"], contributor_node["id"], "authored_by", "low")
    else:
        commit_node = None

    max_source_risk = 0.0
    risky_dependencies = 0
    affected_packages = []
    dep_ids: List[str] = []

    for dep in dependencies:
        dep_id = f"pkg:{dep['ecosystem']}/{dep['name']}@{dep['version']}"
        vulns = fetch_vulnerabilities(dep["name"], dep["ecosystem"]) if fetch_vulns else []

        dep_risk = min(100, sum(SEVERITY_SCORE.get(v.get("severity", "MEDIUM"), 5) for v in vulns))
        if dep_risk > 50:
            risky_dependencies += 1
        max_source_risk = max(max_source_risk, dep_risk)
        affected_packages.append(dep["name"])

        dep_node = _upsert_node(
            nodes_by_id,
            dep_id,
            {
                "name": dep["name"],
                "version": dep["version"],
                "type": "dependency",
                "risk_score": dep_risk,
                "vulnerabilities": vulns,
                "ecosystem": dep["ecosystem"],
            },
        )
        dep_ids.append(dep_id)

        if repo_node:
            _add_edge(edges, repo_node["id"], dep_id, "uses_dependency", _risk_label(dep_risk))
        if commit_node:
            _add_edge(edges, commit_node["id"], dep_id, "touches_dependency", _risk_label(dep_risk))
        _add_edge(edges, contributor_node["id"], dep_id, "introduces", _risk_label(dep_risk))

        for maint in _match_maintainers(dep["name"], maintainers):
            maint_risk = RISK_LEVEL_WEIGHT.get((maint.get("risk_level") or "LOW").upper(), 20)
            maint_id = f"maintainer:{maint['name'].lower()}"
            _upsert_node(
                nodes_by_id,
                maint_id,
                {
                    "name": maint["name"],
                    "type": "maintainer",
                    "risk_score": maint_risk,
                    "risk_level": (maint.get("risk_level") or "LOW").upper(),
                    "exploit_history": maint.get("exploit_history") or "",
                },
            )
            _add_edge(edges, dep_id, maint_id, "maintained_by", _risk_label(maint_risk))
            max_source_risk = max(max_source_risk, maint_risk)

        for vr in _match_vulnerable_repos(dep["name"], vulns, vulnerable_repos):
            vr_risk = RISK_LEVEL_WEIGHT.get((vr.get("severity") or "MEDIUM").upper(), 45)
            vr_id = f"vulnrepo:{vr['name'].lower()}"
            _upsert_node(
                nodes_by_id,
                vr_id,
                {
                    "name": vr["name"],
                    "type": "vulnerable_repo",
                    "risk_score": vr_risk,
                    "severity": (vr.get("severity") or "MEDIUM").upper(),
                    "cve_ids": vr.get("cve_ids") or [],
                    "description": vr.get("description") or "",
                },
            )
            _add_edge(edges, dep_id, vr_id, "connected_to_vulnerable_repo", _risk_label(vr_risk))
            max_source_risk = max(max_source_risk, vr_risk)

    propagated = _propagate_risk(nodes_by_id, edges, decay=0.72, iterations=4)
    for node_id, score in propagated.items():
        nodes_by_id[node_id]["propagated_risk"] = round(score, 1)
        nodes_by_id[node_id]["risk_score"] = max(nodes_by_id[node_id].get("risk_score", 0), round(score, 1))

    pr_risk = nodes_by_id[pr_node["id"]].get("propagated_risk", 0)
    overall_risk = min(100.0, max(max_source_risk, pr_risk, risky_dependencies * 8 + len(dep_ids) * 2))
    threat_level = _threat_level(overall_risk)

    risk_chains = _find_risk_chains(pr_node["id"], nodes_by_id, edges)

    blast_targets = [n for n in nodes_by_id.values() if n.get("type") in {"dependency", "maintainer", "vulnerable_repo"} and n.get("risk_score", 0) >= 45]

    return {
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "overall_risk_score": round(overall_risk, 1),
        "threat_level": threat_level,
        "blast_radius": {
            "affected_count": len(blast_targets),
            "affected_packages": affected_packages,
            "description": (
                f"Propagation touches {len(blast_targets)} high-risk nodes across "
                f"dependency, maintainer, and vulnerable-repo layers."
            ),
        },
        "risk_chains": risk_chains,
        "insights": {
            "risky_dependency_count": risky_dependencies,
            "maintainer_flags": sum(1 for n in nodes_by_id.values() if n.get("type") == "maintainer" and n.get("risk_score", 0) >= 60),
            "connected_vulnerable_repos": sum(1 for n in nodes_by_id.values() if n.get("type") == "vulnerable_repo"),
        },
    }


def _upsert_node(nodes_by_id: Dict[str, Dict], node_id: str, payload: Dict) -> Dict:
    node = nodes_by_id.get(node_id)
    if node:
        node.update(payload)
        return node
    out = {"id": node_id, **payload}
    nodes_by_id[node_id] = out
    return out


def _add_edge(edges: List[Dict], source: str, target: str, edge_type: str, risk: str) -> None:
    for e in edges:
        if e["source"] == source and e["target"] == target and e["type"] == edge_type:
            return
    edges.append({"source": source, "target": target, "type": edge_type, "risk": risk})


def _risk_label(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _threat_level(score: float) -> str:
    if score > 75:
        return "CRITICAL"
    if score > 55:
        return "HIGH"
    if score > 35:
        return "MEDIUM"
    return "LOW"


def _match_maintainers(dep_name: str, maintainers: List[Dict]) -> List[Dict]:
    dep = dep_name.lower()
    matched = []
    for maint in maintainers:
        repos = [r.lower() for r in (maint.get("repositories") or [])]
        if dep in repos:
            matched.append(maint)
    return matched


def _match_vulnerable_repos(dep_name: str, vulns: List[Dict], vulnerable_repos: List[Dict]) -> List[Dict]:
    dep = dep_name.lower()
    vuln_ids = {v.get("cve_id", "").upper() for v in vulns}
    matched = []
    for repo in vulnerable_repos:
        name = (repo.get("name") or "").lower()
        cves = {c.upper() for c in (repo.get("cve_ids") or [])}
        if dep in name or (vuln_ids and cves.intersection(vuln_ids)):
            matched.append(repo)
    return matched


def _propagate_risk(
    nodes_by_id: Dict[str, Dict],
    edges: List[Dict],
    decay: float,
    iterations: int,
) -> Dict[str, float]:
    reverse_adj = defaultdict(list)
    scores = {nid: float(node.get("risk_score", 0.0)) for nid, node in nodes_by_id.items()}

    for e in edges:
        reverse_adj[e["target"]].append(e["source"])

    for _ in range(iterations):
        updated = dict(scores)
        for nid, score in scores.items():
            if score <= 0:
                continue
            for parent in reverse_adj.get(nid, []):
                updated[parent] = max(updated.get(parent, 0.0), score * decay)
        scores = updated
    return scores


def _find_risk_chains(pr_node_id: str, nodes_by_id: Dict[str, Dict], edges: List[Dict]) -> List[Dict]:
    adj = defaultdict(list)
    for e in edges:
        adj[e["source"]].append(e["target"])

    chains = []
    queue = deque([(pr_node_id, [pr_node_id])])
    visited_paths = set()

    while queue:
        node_id, path = queue.popleft()
        if len(path) > 6:
            continue
        for nxt in adj.get(node_id, []):
            new_path = path + [nxt]
            key = tuple(new_path)
            if key in visited_paths:
                continue
            visited_paths.add(key)
            n = nodes_by_id.get(nxt, {})
            if n.get("type") in {"vulnerable_repo", "maintainer"} and n.get("risk_score", 0) >= 50:
                chains.append(
                    {
                        "path": [nodes_by_id[p].get("name", p) for p in new_path if p in nodes_by_id],
                        "risk_score": round(float(n.get("risk_score", 0)), 1),
                        "terminal_type": n.get("type"),
                    }
                )
            queue.append((nxt, new_path))

    chains.sort(key=lambda c: c["risk_score"], reverse=True)
    return chains[:5]


def generate_risk_narrative(graph_data: Dict) -> str:
    """Use Claude to generate a plain-English risk explanation. Falls back to template."""
    try:
        from anthropic import Anthropic
    except ImportError:
        return _template_narrative(graph_data)

    if not settings.ANTHROPIC_API_KEY:
        return _template_narrative(graph_data)

    dep_nodes = [n for n in graph_data["nodes"] if n["type"] == "dependency"]
    if not dep_nodes:
        return "No dependencies detected — no supply-chain risk in this PR."

    deps_summary = "\n".join(
        f"- {n['name']}@{n.get('version', '?')} (risk: {n.get('risk_score', 0)}/100, "
        f"{len(n.get('vulnerabilities', []))} CVEs)"
        for n in dep_nodes
    )

    chains = graph_data.get("risk_chains", [])
    chain_summary = "\n".join(
        f"- {' -> '.join(c.get('path', []))} ({c.get('risk_score', 0)})" for c in chains[:3]
    )

    prompt = (
        "Analyze this PR's dependency risk profile. Respond in 2-3 sentences.\n\n"
        f"Dependencies:\n{deps_summary}\n\n"
        f"Propagation chains:\n{chain_summary or '- none'}\n\n"
        f"Overall Risk Score: {graph_data['overall_risk_score']}/100\n"
        f"Threat Level: {graph_data['threat_level']}\n\n"
        "Format: [THREAT_LEVEL] SUMMARY: one-sentence summary.\n"
        "Then one actionable remediation line. Be concise and technical."
    )

    try:
        client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except Exception as e:
        logger.warning("AI narrative failed, using template: %s", e)
        return _template_narrative(graph_data)


def _template_narrative(graph_data: Dict) -> str:
    """Deterministic fallback when Claude API is unavailable."""
    dep_nodes = [n for n in graph_data["nodes"] if n["type"] == "dependency"]
    if not dep_nodes:
        return "No dependencies detected — no supply-chain risk."

    total_cves = sum(len(n.get("vulnerabilities", [])) for n in dep_nodes)
    risky = [n for n in dep_nodes if n.get("risk_score", 0) > 40]
    level = graph_data["threat_level"]
    chains = graph_data.get("risk_chains", [])

    if not risky:
        return (
            f"[{level}] This PR introduces {len(dep_nodes)} dependencies with "
            f"{total_cves} known advisory entries. No packages exceed the high-risk threshold."
        )

    worst = max(risky, key=lambda n: n.get("risk_score", 0))
    chain_tail = ""
    if chains:
        top = chains[0]
        chain_tail = f" Risk chain: {' -> '.join(top.get('path', []))}."

    return (
        f"[{level}] This PR introduces {len(dep_nodes)} dependencies with "
        f"{total_cves} known CVEs. {worst['name']}@{worst.get('version', '?')} has "
        f"the highest risk score ({worst['risk_score']}/100). "
        f"Consider upgrading or replacing high-risk packages before merging.{chain_tail}"
    )
