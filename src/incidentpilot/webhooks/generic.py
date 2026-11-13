"""Generic normalized webhook parser."""

from __future__ import annotations

import hashlib
from typing import Any

from incidentpilot.models import AlertSource, IncidentEvent, Severity


def parse_generic_webhook(payload: dict[str, Any]) -> list[IncidentEvent]:
    """Parse a generic JSON alert payload."""
    service = str(payload.get("service") or "unknown-service")
    title = str(payload.get("title") or payload.get("message") or "Generic Incident")
    description = str(payload.get("description") or title)
    external_id = str(payload.get("id") or payload.get("external_id") or "generic-1")
    fp = str(
        payload.get("fingerprint")
        or hashlib.sha256(f"generic:{service}:{title}".encode("utf-8")).hexdigest()[:16]
    )
    sev_raw = str(payload.get("severity") or "high").lower()
    severity = Severity(sev_raw) if sev_raw in {s.value for s in Severity} else Severity.HIGH

    return [
        IncidentEvent(
            source=AlertSource.GENERIC,
            external_id=external_id,
            fingerprint=fp,
            service=service,
            environment=str(payload.get("environment") or "production"),
            title=title,
            description=description,
            severity=severity,
            stacktrace_hint=str(payload.get("stacktrace") or ""),
            labels={str(k): str(v) for k, v in (payload.get("labels") or {}).items()},
            raw_payload=payload,
        )
    ]
