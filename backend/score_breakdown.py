"""Explainable score breakdown: map findings into four honest categories.

The scanner emits flat `findings` with a `type` field. `calculate_risk_score`
collapses everything into a 0-100 scalar. This module answers "why is that 78?"
by bucketing findings into four categories that match what the scanner actually
detects — no fabricated dependency scans or CVE databases.

Category score is inverted risk: 100 = clean, 0 = severe. This makes it easy to
render as a progress bar ("how well are we doing on secrets?") rather than a
confusing risk weight.
"""

from typing import Dict, List

from scanner import SEVERITY_WEIGHTS


# Maps scanner finding `type` → breakdown category.
_TYPE_TO_CATEGORY = {
    "SECRET_IN_PROMPT": "secrets",
    "DATA_LEAKAGE": "secrets",
    "DIRECT_INJECTION": "injection",
    "INDIRECT_INJECTION": "injection",
    "ROLE_CONFUSION": "role",
    "OVERLY_PERMISSIVE": "role",
    "SYSTEM_PROMPT_EXPOSED": "leakage",
}

_CATEGORY_LABELS = [
    ("secrets", "Secrets & PII"),
    ("injection", "Prompt injection"),
    ("role", "Role confusion"),
    ("leakage", "System-prompt leak"),
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
) -> Dict:
    """Group findings by category and derive per-source signal weights.

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

    total_signals = max(1, static_count + ai_count)
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
