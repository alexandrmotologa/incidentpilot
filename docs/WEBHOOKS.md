# Webhooks and Security

IncidentPilot provides endpoints for major alerting providers, each with token or signature validation.

## Auto-Resolution and MTTR

When an alert manager, PagerDuty, or Datadog sends a resolution payload, IncidentPilot marks matching active incidents as `resolved`, timestamps the event, and computes `mttr_seconds` from initial trigger to resolution.

## PagerDuty (`/webhooks/pagerduty`)

- Supports PagerDuty V3 (`event.event_type` in `incident.triggered`, `incident.escalated`, `incident.resolved`) and V2 (`messages[]`).
- Verification: `X-PagerDuty-Signature` header (`v1=<hex_hmac_sha256>`) verified against `pagerduty_webhook_secret`.

## Prometheus Alertmanager (`/webhooks/alertmanager`)

- Parses Alertmanager v4 webhook payloads (`alerts[]`, `commonLabels`, `commonAnnotations`).
- Alerts with `status == "resolved"` trigger the auto-resolution pipeline.
- Verification: `Authorization: Bearer <token>` verified against `alertmanager_bearer_token`.

## Sentry (`/webhooks/sentry`)

- Parses issue alert and error event webhooks, reconstructing exception stack frames into structured frames.
- Verification: `Sentry-Hook-Signature` (HMAC-SHA256 hex digest) verified against `sentry_client_secret`.

## Datadog (`/webhooks/datadog`)

- Ingests alert events, metric monitors, and synthetic tests.
- Transition events where `alert_transition` is `Recovered` or `Warn to OK` trigger the auto-resolution pipeline.
- Verification: `DD-WEBHOOK-TOKEN` header verified against `datadog_webhook_token`.

## Generic (`/webhooks/generic`)

Accepts a normalized JSON object for custom monitoring scripts:

```json
{
  "service": "checkout-api",
  "title": "High 5xx rate",
  "description": "panic at pkg/checkout/checkout.go:114",
  "severity": "critical",
  "environment": "production",
  "stacktrace": "panic: nil pointer dereference\n\tpkg/checkout/checkout.go:114"
}
```
