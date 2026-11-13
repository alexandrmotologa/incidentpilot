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
