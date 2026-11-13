# Slack and Rollback Execution

## Slack delivery

Configure either:

- Bot Token mode (`INCIDENTPILOT_SLACK_BOT_TOKEN` + `INCIDENTPILOT_SLACK_CHANNEL`) using `chat.postMessage`, or
- Incoming Webhook mode (`INCIDENTPILOT_SLACK_WEBHOOK_URL`).

To handle `[Confirm Rollback]` and `[Dismiss]` button clicks, point your Slack App Interactivity Request URL to `POST /integrations/slack/actions` and set `INCIDENTPILOT_SLACK_SIGNING_SECRET`. IncidentPilot verifies `X-Slack-Signature` (`v0=...`) and `X-Slack-Request-Timestamp` (rejecting requests older than 300 seconds).

## Rollback providers

`INCIDENTPILOT_ROLLBACK_PROVIDER` selects how confirmed rollbacks execute:

- `local_git`: Runs `INCIDENTPILOT_ROLLBACK_COMMAND` if set (with `INCIDENTPILOT_INCIDENT_ID`, `INCIDENTPILOT_SERVICE`, and `INCIDENTPILOT_TARGET_VERSION` in the environment), or verifies the target ref and runs `git checkout --detach <target_version>` in `INCIDENTPILOT_LOCAL_REPO_PATH`.
- `github_workflow`: Dispatches `INCIDENTPILOT_GITHUB_ROLLBACK_WORKFLOW` via the GitHub Actions API with `version`, `service`, and `incident_id` inputs.
- `webhook`: Sends a `POST` request to `INCIDENTPILOT_ROLLBACK_WEBHOOK_URL` with an optional `X-IncidentPilot-Signature: sha256=...` header signed using `INCIDENTPILOT_ROLLBACK_WEBHOOK_SECRET`.
