# Webhooks and Security

Each monitoring integration has a dedicated endpoint and verification mechanism. Leave the corresponding secret empty during local development to skip verification, or set it in `.env` for production deployments.

## PagerDuty (`/webhooks/pagerduty`)

- Supports PagerDuty V3 (`event.event_type` in `incident.triggered`, `incident.escalated`) and V2 (`messages[]`).
- Verification: `X-PagerDuty-Signature` header (`v1=<hex_hmac_sha256>`) verified against `INCIDENTPILOT_PAGERDUTY_WEBHOOK_SECRET`.

## Prometheus Alertmanager (`/webhooks/alertmanager`)

- Parses v4 webhook payloads (`alerts[]`, `commonLabels`, `commonAnnotations`). Alerts with `status == "resolved"` are ignored.
- Verification: `Authorization: Bearer <token>` verified against `INCIDENTPILOT_ALERTMANAGER_BEARER_TOKEN`.

## Sentry (`/webhooks/sentry`)

- Parses issue alert and error event webhooks, reconstructing exception stack frames into `stacktrace_hint`.
- Verification: `Sentry-Hook-Signature` (HMAC-SHA256 hex digest) verified against `INCIDENTPILOT_SENTRY_CLIENT_SECRET`.

## Generic (`/webhooks/generic`)

Accepts a normalized JSON object:

```json
{
  "service": "checkout-api",
  "title": "High 5xx rate",
  "description": "panic at pkg/checkout/checkout.go:114",
  "severity": "critical",
  "environment": "production",
  "stacktrace": "..."
}
```
