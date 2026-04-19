"""AI analysis layer — Google Vertex AI (Gemini) backend.

Uses the unified `google-genai` SDK in Vertex mode. Authentication is via
Application Default Credentials (`gcloud auth application-default login`)
or a service account JSON pointed to by GOOGLE_APPLICATION_CREDENTIALS.

The AI layer is *additive* on top of the static + dataflow analyzers. It
catches contextual issues regex/AST cannot — e.g. "this tool looks safe in
isolation but is dangerous given the rest of the agent file's behavior".

Specifically tuned to surface OWASP LLM Top 10 (2025) categories:
  • LLM01 — Prompt Injection
  • LLM02 — Sensitive Information Disclosure
  • LLM05 — Improper Output Handling      (LLM_OUTPUT_TO_*)
  • LLM06 — Excessive Agency              (DANGEROUS_TOOL_*, TOOL_*)
  • LLM07 — System Prompt Leakage
"""
from __future__ import annotations

import json
import logging
import re
from typing import Dict, List

from config import settings

try:  # google-genai is optional at import time so unit tests run without it
    from google import genai
    from google.genai import types as genai_types
except ImportError:  # pragma: no cover
    genai = None
    genai_types = None

logger = logging.getLogger("promptshield.ai")


SYSTEM_PROMPT = (
    "You are an expert prompt-security auditor specializing in AI agent and "
    "LLM application security. Analyze the provided prompt or code for "
    "security vulnerabilities. Return ONLY a JSON array of finding objects.\n\n"
    "Each finding object MUST have these fields:\n"
    "  - type (string)\n"
    "  - severity (one of: critical, high, medium, low)\n"
    "  - title (string)\n"
    "  - description (string, 1-2 sentences)\n"
    "  - line_number (integer or null)\n"
    "  - remediation (string, concrete fix in 1 sentence)\n"
    "  - confidence (number between 0 and 1)\n"
    "  - evidence (short quoted snippet from the input, max 140 chars)\n"
    "  - cwe (string, e.g. 'CWE-78')\n"
    "  - owasp (string, e.g. 'LLM06: Excessive Agency')\n\n"
    "Find real vulnerabilities only — no speculation. If the input is clean, "
    "return an empty array [].\n\n"
    "Pay SPECIAL ATTENTION to AI agent and LLM application risks below. "
    "Use the exact `type` strings shown so findings merge cleanly with "
    "static-rule and dataflow findings:\n\n"
    "1. DANGEROUS_TOOL_CAPABILITY — Functions decorated with @tool, @mcp.tool, "
    "@server.tool, or registered via tools=[...] / Tool(...) that perform "
    "dangerous operations (subprocess, os.system, os.remove, shutil.rmtree, "
    "raw cursor.execute) without any input validation, allowlist, or "
    "authorization check. Severity: critical. CWE-78. OWASP: 'LLM06: Excessive Agency'.\n\n"
    "2. TOOL_UNVALIDATED_ARGS — A tool function parameter flows directly into "
    "a dangerous sink (subprocess.run, eval, exec, cursor.execute, open(...,'w'), "
    "requests.get with AI-controlled URL) with no sanitization. "
    "Severity: critical. CWE-78. OWASP: 'LLM06: Excessive Agency'.\n\n"
    "3. TOOL_EXCESSIVE_SCOPE — Tool accepts arbitrary file paths, URLs, table "
    "names, or shell commands with no allowlist, sandbox, or scope restriction. "
    "Severity: high. CWE-732. OWASP: 'LLM06: Excessive Agency'.\n\n"
    "4. LLM_OUTPUT_TO_EXEC — LLM API response content (response.content, "
    "completion.choices[*].message.content, message.text, response.text) is "
    "passed to eval() or exec(). Severity: critical. CWE-95. "
    "OWASP: 'LLM05: Improper Output Handling'.\n\n"
    "5. LLM_OUTPUT_TO_SHELL — LLM output is passed to subprocess.run, "
    "os.system, os.popen, or shell=True invocations. Severity: critical. "
    "CWE-78. OWASP: 'LLM05: Improper Output Handling'.\n\n"
    "6. LLM_OUTPUT_TO_SQL — LLM output is interpolated into raw cursor.execute, "
    "db.execute, or session.execute calls without parameterized queries. "
    "Severity: critical. CWE-89. OWASP: 'LLM05: Improper Output Handling'.\n\n"
    "7. RAG_UNSANITIZED_CONTEXT — Vector-DB retrieval results "
    "(similarity_search, collection.query, retriever.invoke, as_retriever) "
    "are concatenated into a prompt without sanitization or access-control "
    "filtering, enabling indirect prompt injection. Severity: high. "
    "CWE-74. OWASP: 'LLM01: Prompt Injection'.\n\n"
    "8. LLM_OUTPUT_UNESCAPED — LLM response rendered as HTML "
    "(innerHTML, dangerouslySetInnerHTML, |safe in Jinja) without escaping. "
    "Severity: high. CWE-79. OWASP: 'LLM05: Improper Output Handling'.\n\n"
    "Be precise. Prefer fewer high-confidence findings over many speculative ones."
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


def _gemini_client():
    """Build a Vertex AI client. Returns None when AI layer is not configured."""
    if not settings.GOOGLE_CLOUD_PROJECT or genai is None:
        return None
    try:
        return genai.Client(
            vertexai=True,
            project=settings.GOOGLE_CLOUD_PROJECT,
            location=settings.GOOGLE_CLOUD_LOCATION,
        )
    except Exception:
        logger.exception(
            "gemini_client init failed",
            extra={"event": "ai_client_error"},
        )
        return None


def ai_scan(text: str) -> List[Dict]:
    """Run a Gemini security audit over arbitrary prompt or code text.

    Returns a list of normalized findings. Returns [] on any failure path so
    the rest of the scan pipeline keeps working in degraded mode.
    """
    client = _gemini_client()
    if client is None:
        logger.info(
            "ai_scan skipped (no GOOGLE_CLOUD_PROJECT or SDK)",
            extra={"event": "ai_skipped"},
        )
        return []
    try:
        config = genai_types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            temperature=0.1,
            max_output_tokens=2048,
        )
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=USER_PROMPT_TEMPLATE.format(text=text),
            config=config,
        )
        body = (response.text or "").strip()
        findings = _normalize(_extract_json_array(body))
        logger.info(
            "ai_scan completed",
            extra={
                "event": "ai_completed",
                "findings_count": len(findings),
                "model": settings.GEMINI_MODEL,
            },
        )
        return findings
    except Exception:
        logger.exception("ai_scan failed", extra={"event": "ai_error"})
        return []


def generate_risk_narrative(graph_data: Dict, pr_info: Dict | None = None) -> str:
    """Generate a plain-English summary for dependency graph risk.

    Uses Gemini when configured and falls back to a deterministic summary.
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

    client = _gemini_client()
    if client is None:
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
        config = genai_types.GenerateContentConfig(
            temperature=0.2,
            max_output_tokens=320,
        )
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
            config=config,
        )
        return (response.text or "").strip()
    except Exception:
        logger.exception("generate_risk_narrative failed")
        highest = max(dep_nodes, key=lambda n: n.get("risk_score", 0))
        return (
            f"[{threat_level}] This PR introduces {len(dep_nodes)} dependencies with possible supply-chain risk. "
            f"Highest risk package is {highest.get('name')}@{highest.get('version', '?')} "
            f"({highest.get('risk_score', 0)}/100). Review and pin safer versions before merge."
        )
