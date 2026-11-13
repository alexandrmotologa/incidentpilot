"""PagerDuty V2 and V3 webhook payload parser."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from incidentpilot.models import AlertSource, IncidentEvent, Severity


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _map_severity(urgency: str | None, priority: str | None = None) -> Severity:
    val = (priority or urgency or "").lower()
    if val in {"p1", "critical", "sev1", "fatal"}:
        return Severity.CRITICAL
    if val in {"p2", "high", "sev2"}:
        return Severity.HIGH
    if val in {"p3", "medium", "sev3"}:
        return Severity.MEDIUM
    if val in {"p4", "p5", "low", "sev4"}:
        return Severity.LOW
    return Severity.HIGH


def _fingerprint(service: str, title: str, external_id: str) -> str:
    raw = f"pagerduty:{service}:{title or external_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def parse_pagerduty_webhook(payload: dict[str, Any]) -> list[IncidentEvent]:
    """Parse PagerDuty V3 or V2 webhook payloads into normalized IncidentEvents."""
    events: list[IncidentEvent] = []

    # PagerDuty V3 format: {"event": {"event_type": "incident.triggered", "data": {...}}}
    if "event" in payload and isinstance(payload["event"], dict):
        ev = payload["event"]
        event_type = str(ev.get("event_type", ""))
        if event_type and event_type not in {"incident.triggered", "incident.escalated"}:
            return []
        data = ev.get("data", {}) or {}
        service_obj = data.get("service") or {}
        service = (
            service_obj.get("summary")
            or service_obj.get("name")
            or data.get("service_name")
            or "unknown-service"
        )
        title = data.get("title") or data.get("summary") or "PagerDuty Incident"
        external_id = str(data.get("id") or ev.get("id") or "pd-unknown")
        priority_obj = data.get("priority") or {}
        severity = _map_severity(data.get("urgency"), priority_obj.get("summary"))
        body = data.get("body") or {}
        description = body.get("details") if isinstance(body, dict) else str(body)
        if not description:
            description = title
        triggered_at = _parse_dt(ev.get("occurred_at") or data.get("created_at"))
        events.append(
            IncidentEvent(
                source=AlertSource.PAGERDUTY,
                external_id=external_id,
                fingerprint=_fingerprint(service, title, external_id),
                service=service,
                environment=str(data.get("environment") or "production"),
                title=title,
                description=description,
                severity=severity,
                triggered_at=triggered_at,
                stacktrace_hint=description if "at " in description or ".go:" in description or ".py" in description else "",
                labels={"incident_number": str(data.get("number", ""))},
                raw_payload=payload,
            )
        )
        return events

    # PagerDuty V2 format: {"messages": [{"event": "incident.trigger", "incident": {...}}]}
    for msg in payload.get("messages", []) or []:
        ev_name = str(msg.get("event", ""))
        if ev_name and ev_name not in {"incident.trigger", "incident.escalate"}:
            continue
        inc = msg.get("incident") or {}
        service_obj = inc.get("service") or {}
        service = service_obj.get("name") or service_obj.get("summary") or "unknown-service"
        title = inc.get("title") or inc.get("summary") or "PagerDuty Incident"
        external_id = str(inc.get("id") or msg.get("id") or "pd-v2-unknown")
        urgency = inc.get("urgency")
        priority = (inc.get("priority") or {}).get("name") if isinstance(inc.get("priority"), dict) else None
        events.append(
            IncidentEvent(
                source=AlertSource.PAGERDUTY,
                external_id=external_id,
                fingerprint=_fingerprint(service, title, external_id),
                service=service,
                title=title,
                description=inc.get("description") or title,
                severity=_map_severity(urgency, priority),
                triggered_at=_parse_dt(inc.get("created_at") or msg.get("created_on")),
                raw_payload=payload,
            )
        )

    return events
