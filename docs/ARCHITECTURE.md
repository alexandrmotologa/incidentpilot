# Architecture

IncidentPilot runs as a single async FastAPI service backed by SQLite (WAL mode) and an in-process investigation orchestrator.

## Investigation flow

1. Webhook ingestion: An alert arrives at `/webhooks/pagerduty`, `/webhooks/alertmanager`, `/webhooks/sentry`, or `/webhooks/generic`. After signature or token verification, the parser normalizes it into an `IncidentEvent` with a deterministic fingerprint.
2. Deduplication: `IncidentStore.find_active_by_fingerprint` checks whether an active incident with the same fingerprint was created within `INCIDENTPILOT_DEDUP_WINDOW_SECONDS` (default 300s). If so, `alert_count` increments and no duplicate investigation runs.
3. Parallel collection: `IncidentOrchestrator.investigate` runs log collection (last 15 minutes), commit history lookup, and deployment/tag lookup concurrently under `asyncio.wait_for` (`INCIDENTPILOT_INVESTIGATION_TIMEOUT_SECONDS`, default 55s).
4. Stack trace extraction: `parse_stacktrace` extracts structured file paths, line numbers, and function names from both the inbound webhook hint and collected error logs across Go, Python, Node.js/TypeScript, Java, and Rust.
5. Correlation and synthesis: `correlate_incident` ranks candidate commits and selects the previous stable release tag as the rollback target. `synthesize_brief` produces the final `IncidentBrief`.
6. Dispatch and dashboard sync: `SlackClient.send_brief` posts a Block Kit message with `[Confirm Rollback]` and `[Dismiss]` actions, and the orchestrator emits an SSE event to connected dashboard clients.
