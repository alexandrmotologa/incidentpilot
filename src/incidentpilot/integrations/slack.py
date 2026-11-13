"""Slack Block Kit formatter and dispatcher for Incident Briefs."""

from __future__ import annotations

from typing import Any

import httpx

from incidentpilot.config import Settings
from incidentpilot.models import IncidentRecord, IncidentStatus


def build_slack_blocks(record: IncidentRecord) -> list[dict[str, Any]]:
    """Build Slack Block Kit blocks for an IncidentRecord."""
    brief = record.brief
    ev = record.event
    sev = ev.severity.value.upper()

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"[{sev}] Incident Brief: {ev.service}",
                "emoji": False,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{record.id}`"},
                {"type": "mrkdwn", "text": f"*Source:*\n{ev.source.value} ({ev.environment})"},
                {"type": "mrkdwn", "text": f"*Alert:*\n{ev.title}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Investigation Time:*\n{brief.investigation_duration_ms if brief else 0} ms",
                },
            ],
        },
    ]

    if brief:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Probable Cause ({brief.confidence:.0f}% confidence):*\n"
                        f"{brief.probable_cause}\n\n"
                        f"*Recommendation:*\n"
                        f"{brief.recommendation}"
                    ),
                },
            }
        )

        if brief.evidence:
            evidence_lines = "\n".join(f"- {item}" for item in brief.evidence[:5])
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Evidence (last 15m: {brief.error_count_15m} errors):*\n{evidence_lines}",
                        }
                    ],
                }
            )

        if record.status == IncidentStatus.ROLLED_BACK:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Status:* Rolled back to `{brief.rollback_target}`.",
                    },
                }
            )
        elif record.status == IncidentStatus.DISMISSED:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*Status:* Dismissed by on-call engineer."},
                }
            )
        else:
            target = brief.rollback_target or "previous-stable"
            blocks.append(
                {
                    "type": "actions",
                    "block_id": f"incident_actions_{record.id}",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": f"Confirm Rollback ({target})",
                                "emoji": False,
                            },
                            "style": "danger",
                            "action_id": "confirm_rollback",
                            "value": f"{record.id}|{target}",
                            "confirm": {
                                "title": {"type": "plain_text", "text": "Confirm Rollback"},
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"Roll back *{ev.service}* to `{target}`?",
                                },
                                "confirm": {"type": "plain_text", "text": "Execute Rollback"},
                                "deny": {"type": "plain_text", "text": "Cancel"},
                            },
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Dismiss", "emoji": False},
                            "action_id": "dismiss_incident",
                            "value": record.id,
                        },
                    ],
                }
            )

    return blocks


class SlackClient:
    """Dispatches and updates Incident Briefs in Slack."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def send_brief(self, record: IncidentRecord) -> dict[str, Any]:
        """Send an incident brief to Slack via Bot API or Incoming Webhook."""
        blocks = build_slack_blocks(record)
        fallback_text = record.brief.summary if record.brief else record.event.title

        if self.settings.slack_bot_token and self.settings.slack_channel:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://slack.com/api/chat.postMessage",
                    headers={
                        "Authorization": f"Bearer {self.settings.slack_bot_token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "channel": self.settings.slack_channel,
                        "text": fallback_text,
                        "blocks": blocks,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return {
                    "delivered": bool(data.get("ok")),
                    "ts": str(data.get("ts") or ""),
                    "channel": str(data.get("channel") or self.settings.slack_channel),
                    "blocks": blocks,
                }

        if self.settings.slack_webhook_url:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.settings.slack_webhook_url,
                    json={"text": fallback_text, "blocks": blocks},
                )
                resp.raise_for_status()
                return {"delivered": True, "ts": "", "blocks": blocks}

        return {"delivered": False, "reason": "slack_not_configured", "blocks": blocks}

    async def post_response_url(self, response_url: str, record: IncidentRecord) -> None:
        """Update an interactive Slack message via Slack's response_url."""
        if not response_url:
            return
        blocks = build_slack_blocks(record)
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                response_url,
                json={
                    "replace_original": True,
                    "text": record.brief.summary if record.brief else record.event.title,
                    "blocks": blocks,
                },
            )
