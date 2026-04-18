from unittest.mock import patch, MagicMock

import notifications
from notifications import (
    _slack_payload,
    _teams_payload,
    notify_gate_failure,
)


SAMPLE_EVENT = {
    "repo_full_name": "acme/app",
    "pr_number": 42,
    "pr_title": "Add new provider",
    "pr_url": "https://github.com/acme/app/pull/42",
    "risk_score": 83,
    "threshold": 70,
    "counts": {"critical": 1, "high": 2, "medium": 0, "low": 4},
}


def test_slack_payload_has_repo_and_url_button():
    p = _slack_payload(SAMPLE_EVENT)
    assert "acme/app#42" in p["text"]
    assert "83" in p["text"]
    # last block should be an "actions" block with the PR link
    assert any(
        b.get("type") == "actions"
        and b["elements"][0]["url"] == SAMPLE_EVENT["pr_url"]
        for b in p["blocks"]
    )


def test_teams_payload_has_facts():
    p = _teams_payload(SAMPLE_EVENT)
    fact_names = [f["name"] for f in p["sections"][0]["facts"]]
    assert "Repository" in fact_names
    assert "Pull Request" in fact_names
    assert p["@type"] == "MessageCard"


def test_notify_noop_when_no_webhook_configured():
    with patch.object(notifications.settings, "SLACK_WEBHOOK_URL", None), patch.object(
        notifications.settings, "TEAMS_WEBHOOK_URL", None
    ):
        result = notify_gate_failure(SAMPLE_EVENT)
        assert result == {}


def test_notify_slack_posts_to_configured_url():
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value.status_code = 200
    with patch.object(
        notifications.settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.example/T/B/Z"
    ), patch.object(
        notifications.settings, "TEAMS_WEBHOOK_URL", None
    ), patch("notifications.httpx.Client", return_value=mock_client):
        result = notify_gate_failure(SAMPLE_EVENT)
        assert result == {"slack": True}
        mock_client.post.assert_called_once()
        args, kwargs = mock_client.post.call_args
        assert args[0] == "https://hooks.slack.example/T/B/Z"
        assert "blocks" in kwargs["json"]


def test_notify_survives_http_error():
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value.status_code = 500
    mock_client.post.return_value.text = "upstream failure"
    with patch.object(
        notifications.settings, "SLACK_WEBHOOK_URL", "https://slack.example"
    ), patch.object(
        notifications.settings, "TEAMS_WEBHOOK_URL", None
    ), patch("notifications.httpx.Client", return_value=mock_client):
        result = notify_gate_failure(SAMPLE_EVENT)
        assert result == {"slack": False}
