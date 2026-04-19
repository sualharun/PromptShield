"""Build an Agent Attack Surface graph from scan findings.

Converts PromptShield findings (static + dataflow) into a force-directed graph
that shows:
  - Agent node (central)
  - Tool nodes (@tool-decorated functions)
  - Data source nodes (user input, LLM response, RAG retrieval)
  - Dangerous sink nodes (eval, exec, subprocess, cursor.execute)
  - Resource nodes (database, filesystem, shell, network)

Edges trace how data flows from sources through tools into dangerous sinks.
Attack chains show proven exploitation paths.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Set, Tuple


# ── Node type constants ────────────────────────────────────────────────

TOOL_FINDING_TYPES = {
    "DANGEROUS_TOOL_CAPABILITY",
    "TOOL_UNVALIDATED_ARGS",
    "TOOL_EXCESSIVE_SCOPE",
    "DANGEROUS_TOOL_BODY",
    "TOOL_PARAM_TO_EXEC",
    "TOOL_PARAM_TO_SHELL",
    "TOOL_PARAM_TO_SQL",
    "TOOL_UNRESTRICTED_FILE",
}

OUTPUT_FINDING_TYPES = {
    "LLM_OUTPUT_TO_EXEC",
    "LLM_OUTPUT_TO_SHELL",
    "LLM_OUTPUT_TO_SQL",
    "LLM_OUTPUT_UNESCAPED",
    "LLM_OUTPUT_EXEC",
    "LLM_OUTPUT_SHELL",
    "LLM_OUTPUT_SQL",
}

RAG_FINDING_TYPES = {
    "RAG_UNSANITIZED_CONTEXT",
}

INJECTION_FINDING_TYPES = {
    "DIRECT_INJECTION",
    "INDIRECT_INJECTION",
    "DATAFLOW_INJECTION",
}

SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20}

# Maps finding types to the resource they threaten
SINK_TO_RESOURCE = {
    "LLM_OUTPUT_TO_EXEC": "code_execution",
    "LLM_OUTPUT_EXEC": "code_execution",
    "TOOL_PARAM_TO_EXEC": "code_execution",
    "LLM_OUTPUT_TO_SHELL": "shell",
    "LLM_OUTPUT_SHELL": "shell",
    "TOOL_PARAM_TO_SHELL": "shell",
    "DANGEROUS_TOOL_CAPABILITY": "shell",
    "LLM_OUTPUT_TO_SQL": "database",
    "LLM_OUTPUT_SQL": "database",
    "TOOL_PARAM_TO_SQL": "database",
    "TOOL_UNVALIDATED_ARGS": "database",
    "TOOL_EXCESSIVE_SCOPE": "filesystem",
    "TOOL_UNRESTRICTED_FILE": "filesystem",
    "LLM_OUTPUT_UNESCAPED": "browser",
    "RAG_UNSANITIZED_CONTEXT": "llm_context",
    "DIRECT_INJECTION": "llm_context",
    "INDIRECT_INJECTION": "llm_context",
    "DATAFLOW_INJECTION": "llm_context",
}

RESOURCE_LABELS = {
    "code_execution": "Code Execution (eval/exec)",
    "shell": "System Shell",
    "database": "Database",
    "filesystem": "Filesystem",
    "browser": "Browser DOM",
    "llm_context": "LLM Prompt Context",
}


def _extract_tool_name(finding: Dict) -> str | None:
    """Try to extract the @tool function name from finding evidence or title."""
    evidence = finding.get("evidence") or ""
    title = finding.get("title") or ""

    # Look for function name patterns
    _GENERIC_NAMES = {"function", "tool", "def", "class", "method", "the", "a", "an"}
    m = re.search(r"(?:def |tool |Tool )[\"']?(\w+)", evidence + " " + title)
    if m and m.group(1).lower() not in _GENERIC_NAMES:
        return m.group(1)

    # Look for function name in dataflow path
    path = finding.get("dataflow_path") or []
    for step in path:
        m = re.search(r"→\s*(\w+)\(\)", step)
        if m:
            return m.group(1)

    return None


def _extract_sink_name(finding: Dict) -> str:
    """Extract the dangerous sink name from a finding."""
    ftype = finding.get("type", "")
    evidence = finding.get("evidence") or ""
    title = finding.get("title") or ""
    combined = evidence + " " + title

    if "eval" in combined.lower():
        return "eval()"
    if "exec" in combined.lower():
        return "exec()"
    if "subprocess" in combined.lower():
        return "subprocess.run()"
    if "os.system" in combined.lower():
        return "os.system()"
    if "os.remove" in combined.lower():
        return "os.remove()"
    if "os.popen" in combined.lower():
        return "os.popen()"
    if "cursor.execute" in combined.lower() or "db.execute" in combined.lower():
        return "cursor.execute()"
    if "shutil" in combined.lower():
        return "shutil.rmtree()"
    if "innerHTML" in combined:
        return "innerHTML"
    if "similarity_search" in combined:
        return "similarity_search()"

    # Fallback based on type
    if "EXEC" in ftype:
        return "eval()/exec()"
    if "SHELL" in ftype:
        return "subprocess.run()"
    if "SQL" in ftype:
        return "cursor.execute()"
    if "FILE" in ftype or "SCOPE" in ftype:
        return "open()"

    return "dangerous_sink()"


def _detect_tools_from_code(code: str) -> List[Dict]:
    """Parse code to find @tool-decorated functions with AST."""
    tools = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return tools

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        is_tool = False
        for dec in node.decorator_list:
            dec_name = ""
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
            if "tool" in dec_name.lower():
                is_tool = True
                break

        if is_tool:
            params = [a.arg for a in node.args.args if a.arg != "self"]
            docstring = ast.get_docstring(node) or ""
            tools.append({
                "name": node.name,
                "line": node.lineno,
                "params": params,
                "docstring": docstring[:100],
            })

    return tools


def build_agent_graph(
    findings: List[Dict],
    code: str = "",
    scan_context: Dict | None = None,
) -> Dict[str, Any]:
    """Build the Agent Attack Surface graph from findings and source code.

    Returns the same shape as the dependency graph (nodes, edges, risk_chains,
    etc.) so the frontend ForceGraph2D component can render it directly.
    """
    ctx = scan_context or {}
    nodes: List[Dict] = []
    edges: List[Dict] = []
    node_ids: Set[str] = set()
    attack_chains: List[Dict] = []

    # ── 1. Central agent node ──────────────────────────────────────────
    agent_id = "agent:main"
    nodes.append({
        "id": agent_id,
        "name": ctx.get("agent_name", "AI Agent"),
        "type": "agent",
        "risk_score": 0,  # computed later
    })
    node_ids.add(agent_id)

    # ── 2. Discover tools from code (AST) ──────────────────────────────
    code_tools = _detect_tools_from_code(code) if code else []
    tool_names_from_code = {t["name"] for t in code_tools}

    # Also discover tools from findings
    tool_names_from_findings: Set[str] = set()
    for f in findings:
        if f.get("type") in TOOL_FINDING_TYPES:
            name = _extract_tool_name(f)
            if name:
                tool_names_from_findings.add(name)

    # Merge — code tools have more metadata
    all_tool_names = tool_names_from_code | tool_names_from_findings
    tool_nodes: Dict[str, str] = {}  # name → node_id

    for tool_info in code_tools:
        tid = f"tool:{tool_info['name']}"
        if tid in node_ids:
            continue
        # Compute risk from findings that reference this tool
        tool_risk = 0
        for f in findings:
            if f.get("type") in TOOL_FINDING_TYPES:
                tn = _extract_tool_name(f)
                if tn == tool_info["name"]:
                    tool_risk = max(tool_risk, SEVERITY_SCORE.get(f.get("severity", "low"), 20))
        nodes.append({
            "id": tid,
            "name": tool_info["name"],
            "type": "tool",
            "risk_score": tool_risk,
            "params": tool_info["params"],
            "docstring": tool_info["docstring"],
            "line_number": tool_info["line"],
        })
        node_ids.add(tid)
        tool_nodes[tool_info["name"]] = tid
        edges.append({"source": agent_id, "target": tid, "type": "exposes", "risk": "low"})

    # Tools only found in findings (no code available)
    for name in tool_names_from_findings - tool_names_from_code:
        tid = f"tool:{name}"
        if tid in node_ids:
            continue
        tool_risk = 0
        for f in findings:
            if f.get("type") in TOOL_FINDING_TYPES:
                tn = _extract_tool_name(f)
                if tn == name:
                    tool_risk = max(tool_risk, SEVERITY_SCORE.get(f.get("severity", "low"), 20))
        nodes.append({
            "id": tid,
            "name": name,
            "type": "tool",
            "risk_score": tool_risk,
        })
        node_ids.add(tid)
        tool_nodes[name] = tid
        edges.append({"source": agent_id, "target": tid, "type": "exposes", "risk": "low"})

    # ── 3. Data source nodes ───────────────────────────────────────────
    source_nodes: Dict[str, str] = {}  # label → node_id

    # Check findings for data sources
    has_user_input = any(
        f.get("type") in INJECTION_FINDING_TYPES
        or "user input" in (f.get("description") or "").lower()
        or "input()" in (f.get("evidence") or "")
        for f in findings
    )
    has_llm_response = any(f.get("type") in OUTPUT_FINDING_TYPES for f in findings)
    has_rag = any(f.get("type") in RAG_FINDING_TYPES for f in findings)

    # Also detect from code
    if code:
        if re.search(r"\binput\s*\(|request\.\w+|sys\.argv", code):
            has_user_input = True
        if re.search(r"\.messages\.create|\.completions\.create|\.responses\.create", code):
            has_llm_response = True
        if re.search(r"similarity_search|\.query\s*\(|as_retriever", code):
            has_rag = True

    if has_user_input:
        sid = "source:user_input"
        nodes.append({
            "id": sid,
            "name": "User Input",
            "type": "data_source",
            "risk_score": 60,
            "description": "External user-controlled data (input(), request.form, API params)",
        })
        node_ids.add(sid)
        source_nodes["user_input"] = sid

    if has_llm_response:
        sid = "source:llm_response"
        nodes.append({
            "id": sid,
            "name": "LLM Response",
            "type": "data_source",
            "risk_score": 50,
            "description": "Text generated by the LLM (response.content, completion.choices)",
        })
        node_ids.add(sid)
        source_nodes["llm_response"] = sid

    if has_rag:
        sid = "source:rag_retrieval"
        nodes.append({
            "id": sid,
            "name": "RAG Retrieval",
            "type": "data_source",
            "risk_score": 55,
            "description": "Documents retrieved from vector database (similarity_search, collection.query)",
        })
        node_ids.add(sid)
        source_nodes["rag_retrieval"] = sid

    # ── 4. Dangerous sink nodes ────────────────────────────────────────
    sink_nodes: Dict[str, str] = {}  # sink_name → node_id
    sinks_seen: Set[str] = set()

    for f in findings:
        ftype = f.get("type", "")
        if ftype not in (TOOL_FINDING_TYPES | OUTPUT_FINDING_TYPES | RAG_FINDING_TYPES | INJECTION_FINDING_TYPES):
            continue

        sink_name = _extract_sink_name(f)
        if sink_name in sinks_seen or sink_name == "dangerous_sink()":
            continue
        sinks_seen.add(sink_name)

        sink_id = f"sink:{sink_name.replace('()', '').replace('.', '_')}"
        if sink_id in node_ids:
            continue

        sink_risk = SEVERITY_SCORE.get(f.get("severity", "low"), 20)
        nodes.append({
            "id": sink_id,
            "name": sink_name,
            "type": "dangerous_sink",
            "risk_score": sink_risk,
            "line_number": f.get("line_number"),
            "cwe": f.get("cwe"),
            "owasp": f.get("owasp"),
        })
        node_ids.add(sink_id)
        sink_nodes[sink_name] = sink_id

    # ── 5. Resource nodes ──────────────────────────────────────────────
    resource_ids: Dict[str, str] = {}
    resources_needed: Set[str] = set()

    for f in findings:
        resource = SINK_TO_RESOURCE.get(f.get("type", ""))
        if resource:
            resources_needed.add(resource)

    for resource in resources_needed:
        rid = f"resource:{resource}"
        label = RESOURCE_LABELS.get(resource, resource.replace("_", " ").title())
        risk = 80 if resource in ("code_execution", "shell") else 60 if resource == "database" else 40
        nodes.append({
            "id": rid,
            "name": label,
            "type": "resource",
            "risk_score": risk,
        })
        node_ids.add(rid)
        resource_ids[resource] = rid

    # ── 6. Build edges ─────────────────────────────────────────────────

    for f in findings:
        ftype = f.get("type", "")
        severity = f.get("severity", "low")
        risk_label = severity if severity in ("critical", "high") else "medium"
        sink_name = _extract_sink_name(f)
        sink_id = sink_nodes.get(sink_name)
        resource = SINK_TO_RESOURCE.get(ftype)
        resource_id = resource_ids.get(resource) if resource else None
        tool_name = _extract_tool_name(f)
        tool_id = tool_nodes.get(tool_name) if tool_name else None

        # Tool → Sink edges
        if ftype in TOOL_FINDING_TYPES and tool_id and sink_id:
            edges.append({"source": tool_id, "target": sink_id, "type": "calls", "risk": risk_label})

        # LLM Response → Sink edges
        if ftype in OUTPUT_FINDING_TYPES and sink_id:
            llm_src = source_nodes.get("llm_response")
            if llm_src:
                edges.append({"source": llm_src, "target": sink_id, "type": "flows_to", "risk": risk_label})

        # RAG → Agent/LLM context
        if ftype in RAG_FINDING_TYPES:
            rag_src = source_nodes.get("rag_retrieval")
            if rag_src:
                edges.append({"source": rag_src, "target": agent_id, "type": "injects_into", "risk": risk_label})

        # User Input → Tool or Agent
        if ftype in INJECTION_FINDING_TYPES:
            user_src = source_nodes.get("user_input")
            if user_src:
                target = tool_id or agent_id
                edges.append({"source": user_src, "target": target, "type": "flows_to", "risk": risk_label})

        # Sink → Resource edges
        if sink_id and resource_id:
            # Avoid duplicate sink→resource edges
            existing = any(
                e["source"] == sink_id and e["target"] == resource_id
                for e in edges
            )
            if not existing:
                edges.append({"source": sink_id, "target": resource_id, "type": "accesses", "risk": risk_label})

    # ── 7. Compute overall risk ────────────────────────────────────────
    max_risk = max((n["risk_score"] for n in nodes), default=0)
    agent_risk = min(100, sum(
        SEVERITY_SCORE.get(f.get("severity", "low"), 0)
        for f in findings
        if f.get("type") in (TOOL_FINDING_TYPES | OUTPUT_FINDING_TYPES | RAG_FINDING_TYPES)
    ))
    overall_risk = min(100, max(max_risk, agent_risk))

    # Update agent node risk
    for n in nodes:
        if n["id"] == agent_id:
            n["risk_score"] = agent_risk

    # Threat level
    if overall_risk >= 75:
        threat_level = "CRITICAL"
    elif overall_risk >= 55:
        threat_level = "HIGH"
    elif overall_risk >= 35:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # ── 8. Build attack chains ─────────────────────────────────────────
    # Each chain: source → tool/agent → sink → resource
    for f in findings:
        ftype = f.get("type", "")
        if ftype not in (TOOL_FINDING_TYPES | OUTPUT_FINDING_TYPES):
            continue

        chain_path = []
        chain_risk = SEVERITY_SCORE.get(f.get("severity", "low"), 20)
        sink_name = _extract_sink_name(f)
        resource = SINK_TO_RESOURCE.get(ftype)
        tool_name = _extract_tool_name(f)

        # Build the path
        if ftype in TOOL_FINDING_TYPES:
            if "user_input" in source_nodes:
                chain_path.append("User Input")
            if tool_name:
                chain_path.append(tool_name)
            chain_path.append(sink_name)
            if resource:
                chain_path.append(RESOURCE_LABELS.get(resource, resource))
            terminal = "resource"
        else:
            chain_path.append("LLM Response")
            chain_path.append(sink_name)
            if resource:
                chain_path.append(RESOURCE_LABELS.get(resource, resource))
            terminal = "resource"

        if len(chain_path) >= 2:
            attack_chains.append({
                "path": chain_path,
                "risk_score": chain_risk,
                "terminal_type": terminal,
                "finding_type": ftype,
                "description": f.get("title", ""),
            })

    # Sort chains by risk (highest first), deduplicate
    attack_chains.sort(key=lambda c: -c["risk_score"])
    seen_paths: Set[str] = set()
    unique_chains = []
    for chain in attack_chains:
        key = " → ".join(chain["path"])
        if key not in seen_paths:
            seen_paths.add(key)
            unique_chains.append(chain)
    attack_chains = unique_chains[:5]

    # ── 9. Compute insights ────────────────────────────────────────────
    tool_count = sum(1 for n in nodes if n["type"] == "tool")
    dangerous_tool_count = sum(
        1 for n in nodes if n["type"] == "tool" and n["risk_score"] >= 70
    )
    sink_count = sum(1 for n in nodes if n["type"] == "dangerous_sink")
    resource_count = sum(1 for n in nodes if n["type"] == "resource")

    insights = {
        "total_tools": tool_count,
        "dangerous_tools": dangerous_tool_count,
        "dangerous_sinks": sink_count,
        "threatened_resources": resource_count,
        "attack_paths": len(attack_chains),
    }

    # ── 10. Blast radius ───────────────────────────────────────────────
    threatened = [n["name"] for n in nodes if n["type"] == "resource"]
    blast_radius = {
        "affected_count": len(threatened),
        "affected_packages": threatened,
        "description": (
            f"A compromised agent can reach {len(threatened)} system resource(s): "
            + ", ".join(threatened[:4])
            + ("..." if len(threatened) > 4 else "")
        ) if threatened else "No dangerous resources reachable.",
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "overall_risk_score": overall_risk,
        "threat_level": threat_level,
        "blast_radius": blast_radius,
        "risk_chains": attack_chains,
        "insights": insights,
    }
