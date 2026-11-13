"""Sentry Issue / Error Alert webhook parser."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from incidentpilot.models import AlertSource, IncidentEvent, Severity


def _format_sentry_frames(event_data: dict[str, Any]) -> str:
    """Reconstruct a readable stack trace string from Sentry exception frames."""
    exception = event_data.get("exception") or {}
    values = exception.get("values") if isinstance(exception, dict) else []
    if not values:
        return ""

    lines: list[str] = []
    for exc in values:
        exc_type = exc.get("type", "Error")
        exc_val = exc.get("value", "")
        lines.append(f"{exc_type}: {exc_val}")
        stacktrace = exc.get("stacktrace") or {}
        for frame in stacktrace.get("frames", []) or []:
            filename = frame.get("filename") or frame.get("abs_path") or "unknown"
            lineno = frame.get("lineno")
            func = frame.get("function") or "<anonymous>"
            loc = f"{filename}:{lineno}" if lineno else filename
            lines.append(f"  at {func} ({loc})")
    return "\n".join(lines)


def _map_severity(level: str | None) -> Severity:
    val = (level or "").lower()
    if val == "fatal":
        return Severity.CRITICAL
    if val == "error":
        return Severity.HIGH
    if val == "warning":
        return Severity.MEDIUM
    if val in {"info", "debug"}:
        return Severity.LOW
    return Severity.HIGH


def parse_sentry_webhook(payload: dict[str, Any]) -> list[IncidentEvent]:
    """Parse Sentry webhook payload (Issue Alert or Error Event)."""
    data = payload.get("data") or {}
    event_data = data.get("event") or payload.get("event") or {}
    issue_data = data.get("issue") or {}

    if not event_data and not issue_data:
        return []

    service = (
        payload.get("project_name")
        or payload.get("project_slug")
        or event_data.get("project")
        or (issue_data.get("project") or {}).get("slug")
        or "unknown-service"
    )
    title = (
        event_data.get("title")
        or issue_data.get("title")
        or payload.get("message")
        or "Sentry Error"
    )
    culprit = event_data.get("culprit") or issue_data.get("culprit") or ""
    stack_hint = _format_sentry_frames(event_data)
    external_id = str(
        event_data.get("event_id") or issue_data.get("id") or payload.get("id") or "sentry-unknown"
    )
    fp = hashlib.sha256(f"sentry:{service}:{title}:{culprit}".encode("utf-8")).hexdigest()[:16]

    ts_raw = event_data.get("datetime") or event_data.get("timestamp")
    triggered_at = datetime.now(timezone.utc)
    if isinstance(ts_raw, (int, float)):
        triggered_at = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
    elif isinstance(ts_raw, str):
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            triggered_at = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    tags = {}
    for tag in event_data.get("tags", []) or []:
        if isinstance(tag, (list, tuple)) and len(tag) == 2:
            tags[str(tag[0])] = str(tag[1])

    return [
        IncidentEvent(
            source=AlertSource.SENTRY,
            external_id=external_id,
            fingerprint=fp,
            service=str(service),
            environment=str(event_data.get("environment") or tags.get("environment") or "production"),
            title=str(title),
            description=culprit or str(title),
            severity=_map_severity(event_data.get("level") or issue_data.get("level")),
            triggered_at=triggered_at,
            stacktrace_hint=stack_hint,
            labels=tags,
            raw_payload=payload,
        )
    ]
