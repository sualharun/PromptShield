"""Explainable score breakdown: map findings into honest categories.

The scanner emits flat `findings` with a `type` field. `calculate_risk_score`
collapses everything into a 0-100 scalar. This module answers "why is that 78?"
by bucketing findings into categories that match what the scanner actually
detects — no fabricated dependency scans or CVE databases.

Category score is inverted risk: 100 = clean, 0 = severe. This makes it easy to
render as a progress bar ("how well are we doing on secrets?") rather than a
confusing risk weight.

Categories surfaced (v0.5+, agentic-aware):
  • secrets    — Secrets & PII
  • injection  — Prompt injection (incl. RAG context injection)
  • role       — Role confusion / overly permissive prompts
  • leakage    — System-prompt leakage
  • tools      — Agent tool security      (OWASP LLM06: Excessive Agency)
  • output     — LLM output handling      (OWASP LLM05: Improper Output Handling)
"""

from typing import Dict, List

from scanner import SEVERITY_WEIGHTS


# Maps scanner finding `type` → breakdown category.
_TYPE_TO_CATEGORY = {
    # Original prompt-vulnerability categories
    "SECRET_IN_PROMPT": "secrets",
    "DATA_LEAKAGE": "secrets",
    "DIRECT_INJECTION": "injection",
    "INDIRECT_INJECTION": "injection",
    "ROLE_CONFUSION": "role",
    "OVERLY_PERMISSIVE": "role",
    "SYSTEM_PROMPT_EXPOSED": "leakage",
    # Agent tool security (OWASP LLM06: Excessive Agency)
    "DANGEROUS_TOOL_CAPABILITY": "tools",
    "TOOL_UNVALIDATED_ARGS": "tools",
    "TOOL_EXCESSIVE_SCOPE": "tools",
    "DANGEROUS_TOOL_BODY": "tools",
    "TOOL_PARAM_TO_SINK": "tools",
    "TOOL_PARAM_TO_EXEC": "tools",
    "TOOL_PARAM_TO_SHELL": "tools",
    "TOOL_PARAM_TO_SQL": "tools",
    "TOOL_UNRESTRICTED_FILE": "tools",
    # LLM output handling (OWASP LLM05: Improper Output Handling)
    "LLM_OUTPUT_TO_EXEC": "output",
    "LLM_OUTPUT_TO_SHELL": "output",
    "LLM_OUTPUT_TO_SQL": "output",
    "LLM_OUTPUT_UNESCAPED": "output",
    "LLM_OUTPUT_EXEC": "output",
    "LLM_OUTPUT_SHELL": "output",
    "LLM_OUTPUT_SQL": "output",
    # RAG context injection rolls into the existing prompt-injection bucket
    "RAG_UNSANITIZED_CONTEXT": "injection",
    # Agent-security analyzer (agent_security_scan.py) types
    "AGENT_FUNCTION_EXPOSURE": "tools",
    "DANGEROUS_SINK": "tools",
    "UNVALIDATED_FUNCTION_PARAM_TO_SINK": "tools",
    # Dataflow-detected user-input → LLM injection
    "DATAFLOW_INJECTION": "injection",
}

_CATEGORY_LABELS = [
    ("secrets", "Secrets & PII"),
    ("injection", "Prompt injection"),
    ("role", "Role confusion"),
    ("leakage", "System-prompt leak"),
    ("tools", "Agent tool security"),
    ("output", "LLM output handling"),
]


def _category_score(findings: List[Dict]) -> int:
    """100 = clean, 0 = severe. Uses same weights as the global risk score."""
    penalty = sum(
        SEVERITY_WEIGHTS.get(f.get("severity", "low"), 0) for f in findings
    )
    return max(0, 100 - min(100, penalty))


def _confidence_from_findings(findings: List[Dict]) -> str:
    """Confidence in a category: the max confidence of findings in that bucket.
    If nothing landed in the bucket, we're 'high' confident it's clean (the
    scanner ran and found nothing), unless there was no scan at all."""
    if not findings:
        return "high"
    top = max(float(f.get("confidence", 0) or 0) for f in findings)
    if top >= 0.85:
        return "high"
    if top >= 0.6:
        return "medium"
    return "low"


def _category_why(key: str, findings: List[Dict]) -> str:
    if not findings:
        messages = {
            "secrets": "No hardcoded secrets or PII detected.",
            "injection": "No unsanitized user input concatenation detected.",
            "role": "No jailbreak or role-override phrasing detected.",
            "leakage": "No unguarded confidential-instruction patterns detected.",
            "tools": "No dangerous AI-exposed tools or unvalidated tool parameters detected.",
            "output": "No unsafe execution of LLM-generated output detected.",
        }
        return messages.get(key, "No issues detected in this category.")
    # Surface the highest-severity finding's title.
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = min(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 9))
    return top.get("title") or "Issue detected in this category."


def compute_breakdown(
    findings: List[Dict],
    static_count: int,
    ai_count: int,
    dataflow_count: int = 0,
) -> Dict:
    """Group findings by category and derive per-source signal weights.

    `dataflow_count` is optional (defaults to 0) so existing callers and tests
    that pre-date the dataflow signal continue to work unchanged.

    Returns a dict with `categories` and `signals` keys suitable for JSON
    persistence and direct rendering on the Report page.
    """
    buckets: Dict[str, List[Dict]] = {key: [] for key, _ in _CATEGORY_LABELS}
    for f in findings or []:
        category = _TYPE_TO_CATEGORY.get(f.get("type"))
        if category and category in buckets:
            buckets[category].append(f)

    categories = [
        {
            "key": key,
            "label": label,
            "score": _category_score(buckets[key]),
            "confidence": _confidence_from_findings(buckets[key]),
            "why": _category_why(key, buckets[key]),
            "finding_count": len(buckets[key]),
        }
        for key, label in _CATEGORY_LABELS
    ]

    total_signals = max(1, static_count + ai_count + dataflow_count)
    signals = [
        {
            "source": "static",
            "weight_pct": round(100 * static_count / total_signals),
            "confidence": "high" if static_count else "low",
        },
        {
            "source": "ai",
            "weight_pct": round(100 * ai_count / total_signals),
            "confidence": "medium" if ai_count else "low",
        },
        {
            "source": "dataflow",
            "weight_pct": round(100 * dataflow_count / total_signals),
            "confidence": "high" if dataflow_count else "low",
        },
    ]

    return {"categories": categories, "signals": signals}


def render_breakdown_markdown(breakdown: Dict) -> str:
    """Render the breakdown as a GitHub Check Run markdown table."""
    if not breakdown or not breakdown.get("categories"):
        return ""
    lines = [
        "",
        "**Score breakdown**",
        "",
        "| Category | Score | Confidence | Why |",
        "| --- | --- | --- | --- |",
    ]
    for c in breakdown["categories"]:
        lines.append(
            f"| {c['label']} | {c['score']}/100 | {c['confidence']} | {c['why']} |"
        )
    return "\n".join(lines)
