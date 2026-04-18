"""Opt-in outbound notifications (Slack / Teams).

Only fires when the corresponding `*_WEBHOOK_URL` env var is set. Callers
pass a structured event dict and we POST a payload shaped for each target.
Network errors are swallowed with a warning — notifications must never block
the scan pipeline.
"""

import logging
from typing import Dict, List, Optional

import httpx

from config import settings

logger = logging.getLogger("promptshield.notifications")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}


def _slack_payload(event: Dict) -> Dict:
    repo = event.get("repo_full_name") or "?"
    pr = event.get("pr_number")
    score = event.get("risk_score")
    threshold = event.get("threshold")
    url = event.get("pr_url") or ""
    counts = event.get("counts") or {}
    sev_line = " · ".join(
        f"{SEVERITY_EMOJI.get(k, '•')} {k} {v}"
        for k, v in counts.items()
        if v
    ) or "no severity breakdown"
    title = (
        f"PromptShield gate failed — {repo}#{pr} scored {score} "
        f"(threshold {threshold})"
    )
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Findings:* {sev_line}"},
        },
    ]
    if url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open PR"},
                        "url": url,
                    }
                ],
            }
        )
    return {"text": title, "blocks": blocks}


def _teams_payload(event: Dict) -> Dict:
    repo = event.get("repo_full_name") or "?"
    pr = event.get("pr_number")
    score = event.get("risk_score")
    threshold = event.get("threshold")
    url = event.get("pr_url")
    counts = event.get("counts") or {}
    facts: List[Dict] = [
        {"name": "Repository", "value": repo},
        {"name": "Pull Request", "value": f"#{pr}" if pr else "—"},
        {"name": "Risk score", "value": f"{score} / threshold {threshold}"},
    ]
    for k in ("critical", "high", "medium", "low"):
        if counts.get(k):
            facts.append({"name": k.title(), "value": str(counts[k])})
    card: Dict = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "PromptShield gate failure",
        "themeColor": "da1e28",
        "title": f"Gate failed — {repo}#{pr}",
        "sections": [{"facts": facts}],
    }
    if url:
        card["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "Open PR",
                "targets": [{"os": "default", "uri": url}],
            }
        ]
    return card


def _post(url: str, payload: Dict) -> bool:
    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.post(url, json=payload)
            if r.status_code >= 400:
                logger.warning(
                    "notification failed",
                    extra={
                        "event": "notification_failed",
                        "status": r.status_code,
                        "body": r.text[:200],
                    },
                )
                return False
            return True
    except Exception as e:
        logger.warning(
            "notification exception",
            extra={"event": "notification_exception", "error": str(e)},
        )
        return False


def notify_gate_failure(event: Dict) -> Dict[str, bool]:
    """Fire Slack + Teams notifications if configured. Returns a dict of
    {channel: sent_bool} for callers that want to log / audit."""
    result: Dict[str, bool] = {}
    if settings.SLACK_WEBHOOK_URL:
        result["slack"] = _post(settings.SLACK_WEBHOOK_URL, _slack_payload(event))
    if settings.TEAMS_WEBHOOK_URL:
        result["teams"] = _post(settings.TEAMS_WEBHOOK_URL, _teams_payload(event))
    return result
