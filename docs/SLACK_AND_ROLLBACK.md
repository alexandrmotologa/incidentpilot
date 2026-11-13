# Slack and Rollback Execution

## Slack Notifications

Configure either:

- Bot Token mode (`bot_token` + `channel` in `incidentpilot.yaml`) using `chat.postMessage`, or
- Incoming Webhook mode (`webhook_url`).

Per-service overrides in `incidentpilot.yaml` redirect notifications to service-specific channels (such as `#oncall-billing` or `#oncall-checkout`).

To handle `[Confirm Rollback]` and `[Dismiss]` button clicks, point your Slack App Interactivity Request URL to `POST /integrations/slack/actions` and configure `signing_secret`. IncidentPilot verifies `X-Slack-Signature` (`v0=...`) and `X-Slack-Request-Timestamp` (rejecting requests older than 300 seconds).

## Rollback Execution Providers

The `mitigation.rollback_provider` setting selects how confirmed rollbacks execute:

- `local_git`: Verifies the target ref and runs `git checkout --detach <target_version>` in `local_repo_path`. If `rollback_command` is specified, it executes the custom command (such as `kubectl rollout undo deployment/checkout-api -n prod`) with `INCIDENTPILOT_INCIDENT_ID`, `INCIDENTPILOT_SERVICE`, and `INCIDENTPILOT_TARGET_VERSION` passed in the process environment.
- `github_workflow`: Dispatches a GitHub Actions workflow (default: `rollback.yml`) via the GitHub API with `version`, `service`, and `incident_id` input parameters.
- `webhook`: Sends a signed `POST` request to `rollback_webhook_url` with an `X-IncidentPilot-Signature: sha256=...` header signed using `rollback_webhook_secret`.

All rollback actions generate an audit record stored in SQLite containing the executor, timestamp, target version, stdout/stderr output, and execution status.

## Closed-Loop Health Verification

When a rollback completes, IncidentPilot automatically enters an active verification state (`status: rolled_back`, `verification_state: verifying`). A background health monitor polls Prometheus error rate metrics and Loki/JSONL log error counts over a configurable verification window (default: 30 seconds):

- **Healthy Recovery (`verified_healthy`)**: If post-rollback error rates drop below baseline thresholds, the incident transitions to `verified_healthy`, a confirmation is posted to the Slack thread, and a SSE notification updates the War Room Studio.
- **Escalation Required (`escalated`)**: If error rates do not decline within the verification window, the incident transitions to `escalated`, an urgent paging notification is dispatched to Slack, and on-call responders are alerted for manual triage.

## Declarative Auto-Rollback Guardrails

IncidentPilot supports hands-free remediation through strict declarative guardrails configured per service:

```yaml
mitigation:
  allow_auto_rollback: true
  auto_rollback:
    enabled: true
    environments: ["staging", "canary"]
    min_confidence: 90.0
    min_spike_ratio: 5.0
    max_rollback_age_hours: 48
```

Auto-rollback will only execute if all four guardrails pass:
1. Current deployment environment matches an approved environment list.
2. Correlation confidence score meets or exceeds `min_confidence` (e.g. >= 90%).
3. Telemetry error spike ratio meets or exceeds `min_spike_ratio` (e.g. >= 5.0x baseline).
4. Suspect commit age does not exceed `max_rollback_age_hours` (preventing rollbacks across distant schema migrations).

## Slack Thread Assistant Co-Pilot

Engineers can interact with IncidentPilot directly inside any incident's Slack notification thread. Mentioning `@incidentpilot` triggers contextual answers:

- `@incidentpilot diff`: Posts the exact Git unified diff of the suspect commit.
- `@incidentpilot logs`: Posts recent error log lines and stack traces captured during the incident window.
- `@incidentpilot status`: Displays the current lifecycle status, verification outcome, and MTTR.
- `@incidentpilot postmortem`: Formats and shares the executive root cause summary and preventative action items.

## Two-Way Monitoring Sync

IncidentPilot keeps upstream monitoring platforms synchronized with incident lifecycle states:
- **PagerDuty**: Automatically acknowledges incoming incidents via the PagerDuty REST API and writes investigation diagnostic notes directly to the incident timeline.
- **Sentry**: Publishes comments to the corresponding Sentry issue detailing suspect commit SHAs, author attribution, and rollback status.
