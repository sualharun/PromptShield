import json
import logging
import re
from typing import List, Dict

from config import settings

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

logger = logging.getLogger("promptshield.ai")

SYSTEM_PROMPT = (
    "You are an expert prompt security auditor. Analyze the provided prompt or code "
    "for security vulnerabilities. Return ONLY a JSON array of findings. Each finding "
    "must have: type (string), severity (critical|high|medium|low), title (string), "
    "description (string, 1-2 sentences), line_number (integer or null), "
    "remediation (string, concrete fix in 1 sentence), confidence (number between 0 and 1), "
    "evidence (short quoted snippet from the input, max 140 chars). "
    "Find real vulnerabilities only. Be precise."
)


def _extract_json_array(text: str) -> List[Dict]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _normalize(raw: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "low")).lower()
        if sev not in {"critical", "high", "medium", "low"}:
            sev = "low"
        try:
            confidence = float(f.get("confidence", 0.6))
        except (TypeError, ValueError):
            confidence = 0.6
        confidence = max(0.0, min(1.0, confidence))
        line = f.get("line_number")
        if not isinstance(line, int):
            line = None
        evidence = str(f.get("evidence") or "")[:140]
        out.append(
            {
                "type": str(f.get("type", "UNKNOWN")),
                "severity": sev,
                "title": str(f.get("title", "Untitled finding")),
                "description": str(f.get("description", "")),
                "line_number": line,
                "remediation": str(f.get("remediation", "")),
                "source": "ai",
                "confidence": confidence,
                "evidence": evidence,
                "cwe": str(f.get("cwe") or ""),
                "owasp": str(f.get("owasp") or ""),
            }
        )
    return out


def ai_scan(text: str) -> List[Dict]:
    if not settings.ANTHROPIC_API_KEY or Anthropic is None:
        logger.info("ai_scan skipped (no API key or SDK)", extra={"event": "ai_skipped"})
        return []
    try:
        client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze the following prompt or code for vulnerabilities:\n\n```\n{text}\n```",
                }
            ],
        )
        body = "".join(
            block.text for block in msg.content if getattr(block, "type", "") == "text"
        )
        findings = _normalize(_extract_json_array(body))
        logger.info(
            "ai_scan completed",
            extra={"event": "ai_completed", "findings_count": len(findings)},
        )
        return findings
    except Exception:
        logger.exception("ai_scan failed", extra={"event": "ai_error"})
        return []


def generate_risk_narrative(graph_data: Dict, pr_info: Dict | None = None) -> str:
    """Generate a plain-English summary for dependency graph risk.

    Uses Claude when configured and falls back to a deterministic summary.
    """
    dep_nodes = [n for n in graph_data.get("nodes", []) if n.get("type") == "dependency"]
    if not dep_nodes:
        return "No dependency risk detected for this PR."

    deps_summary = "\n".join(
        f"- {n.get('name')}@{n.get('version', '?')} (risk: {n.get('risk_score', 0)}/100) "
        f"{len(n.get('vulnerabilities', []))} CVEs"
        for n in dep_nodes
    )

    threat_level = graph_data.get("threat_level", "LOW")
    risk_score = graph_data.get("overall_risk_score", 0)
    pr_context = pr_info or {}

    if not settings.ANTHROPIC_API_KEY or Anthropic is None:
        highest = max(dep_nodes, key=lambda n: n.get("risk_score", 0))
        return (
            f"[{threat_level}] This PR introduces {len(dep_nodes)} dependencies with possible supply-chain risk. "
            f"Highest risk package is {highest.get('name')}@{highest.get('version', '?')} "
            f"({highest.get('risk_score', 0)}/100). Review and pin safer versions before merge."
        )

    prompt = f"""Analyze this PR's dependency risk profile and explain in 2-3 sentences, plain English.

PR context: {json.dumps(pr_context)}

Dependencies introduced:
{deps_summary}

Overall Risk Score: {risk_score}/100
Threat Level: {threat_level}

Format your response as:
[THREAT_LEVEL] RISK SUMMARY: [1-sentence summary]
[Actionable recommendation or remediation step]

Be concise and technical but accessible."""

    try:
        client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=220,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        ).strip()
    except Exception:
        logger.exception("generate_risk_narrative failed")
        highest = max(dep_nodes, key=lambda n: n.get("risk_score", 0))
        return (
            f"[{threat_level}] This PR introduces {len(dep_nodes)} dependencies with potential CVE exposure. "
            f"Most risky package: {highest.get('name')} ({highest.get('risk_score', 0)}/100). "
            "Recommendation: upgrade or replace the highest-risk transitive dependencies before merge."
        )
