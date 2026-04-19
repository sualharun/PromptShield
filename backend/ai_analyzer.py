import json
import logging
import re
from typing import List, Dict

from config import settings

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

try:
    from google import genai
except ImportError:
    genai = None

logger = logging.getLogger("promptshield.ai")

SYSTEM_PROMPT = (
    "You are an expert prompt security auditor. Analyze the provided prompt or code "
    "for security vulnerabilities. Return ONLY a JSON array of findings. Each finding "
    "must have: type (string), severity (critical|high|medium|low), title (string), "
    "description (string, 1-2 sentences), line_number (integer or null), "
    "remediation (string, concrete fix in 1 sentence), confidence (number between 0 and 1), "
    "evidence (short quoted snippet from the input, max 140 chars), "
    "cwe (string, e.g. CWE-78), owasp (string, e.g. LLM07). "
    "Find real vulnerabilities only. Be precise.\n\n"
    "Additionally, analyze for AI agent security risks (OWASP LLM07 and LLM02):\n"
    "- Functions decorated with @tool or registered via tools=[] that perform dangerous operations "
    "(shell commands, file deletion, database queries, code execution) without input validation "
    "or authorization checks. Flag as DANGEROUS_TOOL_CAPABILITY or TOOL_UNVALIDATED_ARGS.\n"
    "- LLM API response content (response.content, completion.choices, message.text) being passed "
    "to eval(), exec(), subprocess, os.system(), or raw SQL cursor.execute(). "
    "Flag as LLM_OUTPUT_TO_EXEC, LLM_OUTPUT_TO_SHELL, or LLM_OUTPUT_TO_SQL.\n"
    "- Vector database retrieval results (similarity_search, collection.query) concatenated into "
    "prompts without sanitization. Flag as RAG_UNSANITIZED_CONTEXT.\n"
    "- Tool functions with unrestricted scope (can access any file path, any DB table, any URL). "
    "Flag as TOOL_EXCESSIVE_SCOPE.\n"
    "Map findings to CWE-78, CWE-89, CWE-95, CWE-74 and OWASP LLM07 or LLM02 as appropriate."
)

USER_PROMPT_TEMPLATE = "Analyze the following prompt or code for vulnerabilities:\n\n```\n{text}\n```"


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


def _resolve_provider() -> str:
    """Determine which AI provider to use: 'anthropic', 'gemini', or 'none'."""
    explicit = settings.AI_PROVIDER
    if explicit in ("anthropic", "gemini"):
        return explicit
    if settings.ANTHROPIC_API_KEY and Anthropic is not None:
        return "anthropic"
    if settings.GOOGLE_CLOUD_PROJECT and genai is not None:
        return "gemini"
    return "none"


def _scan_anthropic(text: str) -> List[Dict]:
    client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model=settings.AI_MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": USER_PROMPT_TEMPLATE.format(text=text),
            }
        ],
    )
    body = "".join(
        block.text for block in msg.content if getattr(block, "type", "") == "text"
    )
    return _normalize(_extract_json_array(body))


def _scan_gemini(text: str) -> List[Dict]:
    client = genai.Client(
        vertexai=True,
        project=settings.GOOGLE_CLOUD_PROJECT,
        location=settings.GOOGLE_CLOUD_LOCATION,
    )
    response = client.models.generate_content(
        model=settings.GEMINI_MODEL,
        contents=f"{SYSTEM_PROMPT}\n\n{USER_PROMPT_TEMPLATE.format(text=text)}",
    )
    body = response.text or ""
    return _normalize(_extract_json_array(body))


def ai_scan(text: str) -> List[Dict]:
    provider = _resolve_provider()
    if provider == "none":
        logger.info("ai_scan skipped (no AI provider configured)", extra={"event": "ai_skipped"})
        return []
    try:
        if provider == "anthropic":
            findings = _scan_anthropic(text)
        else:
            findings = _scan_gemini(text)
        logger.info(
            "ai_scan completed",
            extra={"event": "ai_completed", "provider": provider, "findings_count": len(findings)},
        )
        return findings
    except Exception:
        logger.exception("ai_scan failed", extra={"event": "ai_error", "provider": provider})
        return []


def generate_risk_narrative(graph_data: Dict, pr_info: Dict | None = None) -> str:
    """Generate a plain-English summary for dependency graph risk.

    Uses the configured AI provider and falls back to a deterministic summary.
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

    def _fallback() -> str:
        highest = max(dep_nodes, key=lambda n: n.get("risk_score", 0))
        return (
            f"[{threat_level}] This PR introduces {len(dep_nodes)} dependencies with possible supply-chain risk. "
            f"Highest risk package is {highest.get('name')}@{highest.get('version', '?')} "
            f"({highest.get('risk_score', 0)}/100). Review and pin safer versions before merge."
        )

    provider = _resolve_provider()
    if provider == "none":
        return _fallback()

    try:
        if provider == "anthropic":
            client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
            message = client.messages.create(
                model=settings.AI_MODEL,
                max_tokens=220,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(
                block.text for block in message.content if getattr(block, "type", "") == "text"
            ).strip()
        else:
            client = genai.Client(
                vertexai=True,
                project=settings.GOOGLE_CLOUD_PROJECT,
                location=settings.GOOGLE_CLOUD_LOCATION,
            )
            response = client.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt,
            )
            return (response.text or "").strip()
    except Exception:
        logger.exception("generate_risk_narrative failed")
        return _fallback()
