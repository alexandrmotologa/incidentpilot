# Architecture

IncidentPilot runs as a single async FastAPI service backed by SQLite (WAL mode) and an in-process investigation orchestrator.

## Investigation flow

1. Webhook ingestion: An alert arrives at `/webhooks/pagerduty`, `/webhooks/alertmanager`, `/webhooks/sentry`, or `/webhooks/generic`. After signature or token verification, the parser normalizes it into an `IncidentEvent` with a deterministic fingerprint.
2. Auto-resolution and MTTR: If the webhook carries a resolution event (`status: "resolved"` or `event_type: "incident.resolved"`), the orchestrator resolves matching active incidents and computes the exact MTTR (Mean Time to Resolution) in seconds.
3. Deduplication: `IncidentStore.find_active_by_fingerprint` checks whether an active incident with the same fingerprint was created within `INCIDENTPILOT_DEDUP_WINDOW_SECONDS` (default 300s). If so, `alert_count` increments and no duplicate investigation runs.
4. Per-service routing: `routing.resolve_settings_for_service` checks `services.yaml` for custom repositories, Slack channels, and rollback providers.
5. Parallel collection and baseline comparison: `IncidentOrchestrator.investigate` collects error logs for the last 15 minutes, queries a prior 45-minute baseline window to calculate error spike ratios, and pulls commit history and release tags concurrently under `asyncio.wait_for`.
6. Stack trace extraction and git blame: `parse_stacktrace` extracts structured frames across Go, Python, Node.js/TypeScript, Java, and Rust. The orchestrator runs `git blame` against the crash lines to pinpoint who authored them.
7. Correlation and runbook matching: `correlate_incident` scores candidate commits. `match_runbooks` evaluates the alert against built-in and custom runbooks (`runbooks.yaml`) for operational issues like OOMKilled containers or connection pool exhaustion.
8. Dispatch and dashboard sync: `SlackClient.send_brief` posts a Block Kit message with `[Confirm Rollback]` and `[Dismiss]` actions, and the orchestrator emits an SSE event to connected dashboard clients.
