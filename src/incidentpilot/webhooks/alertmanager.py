"""Prometheus Alertmanager webhook parser."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from incidentpilot.models import AlertSource, IncidentEvent, Severity


def _parse_dt(value: str | None) -> datetime:
    if not value or value.startswith("0001-01-01"):
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _map_severity(val: str | None) -> Severity:
    s = (val or "").lower()
    if s in {"critical", "page", "fatal", "p1"}:
        return Severity.CRITICAL
    if s in {"warning", "warn", "medium"}:
        return Severity.MEDIUM
    if s in {"info", "low"}:
        return Severity.LOW
    return Severity.HIGH


def parse_alertmanager_webhook(payload: dict[str, Any]) -> list[IncidentEvent]:
    """Parse Prometheus Alertmanager v4 webhook payload."""
    alerts = payload.get("alerts") or []
    common_labels = payload.get("commonLabels") or {}
    common_annotations = payload.get("commonAnnotations") or {}
    events: list[IncidentEvent] = []

    for idx, alert in enumerate(alerts):
        status = str(alert.get("status", "firing")).lower()
        is_resolved = status == "resolved"
        labels = {**common_labels, **(alert.get("labels") or {})}
        annotations = {**common_annotations, **(alert.get("annotations") or {})}

        service = (
            labels.get("service")
            or labels.get("app")
            or labels.get("job")
            or labels.get("container")
            or "unknown-service"
        )
        alertname = labels.get("alertname") or "AlertmanagerAlert"
        title = annotations.get("summary") or f"{alertname} on {service}"
        description = annotations.get("description") or title
        fp = alert.get("fingerprint") or hashlib.sha256(
            f"am:{service}:{alertname}".encode("utf-8")
        ).hexdigest()[:16]

        events.append(
            IncidentEvent(
                source=AlertSource.ALERTMANAGER,
                external_id=f"{fp}-{idx}",
                fingerprint=str(fp),
                service=str(service),
                environment=str(labels.get("env") or labels.get("environment") or "production"),
                title=str(title),
                description=str(description),
                severity=_map_severity(labels.get("severity")),
                triggered_at=_parse_dt(alert.get("startsAt")),
                labels={str(k): str(v) for k, v in labels.items()},
                raw_payload=alert,
                is_resolved=is_resolved,
            )
        )

    return events
