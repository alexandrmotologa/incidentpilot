# Architecture

IncidentPilot runs as a single compiled Go daemon with an embedded React 19 War Room Studio, backed by SQLite in WAL mode and an in-process investigation orchestrator.

## System Topology

```
                         +-----------------------------+
                         |      Monitoring Sources     |
                         | PagerDuty, Alertmanager,    |
                         | Sentry, Datadog, Generic    |
                         +--------------+--------------+
                                        |
                                        v Webhook Ingestion (HMAC/Bearer)
                         +--------------+--------------+
                         | IncidentPilot Single Binary |
                         | (< 25MB RAM, Pure-Go SQLite)|
                         +--------------+--------------+
                                        |
             +--------------------------+--------------------------+
             |                                                     |
             v                                                     v
+-------------------------------+             +----------------------------------+
| Telemetry & Git Collectors    |             | SRE Investigation Engine         |
| - Loki / JSONL error logs     |             | - AST & Diff Proximity Correlator|
| - Prometheus metric queries   | ----------> | - Git Blame Line Attribution     |
| - Git history & deployments   |             | - Baseline Spike Ratio (15m/45m) |
| - Universal stack trace parser|             | - Operational Runbook Matcher    |
+-------------------------------+             +-----------------+----------------+
                                                                |
                                        +-----------------------+
                                        |
                                        v
                         +--------------+--------------+
                         |     Synthesized Incident    |
                         |            Brief            |
                         +--------------+--------------+
                                        |
             +--------------------------+--------------------------+
             |                                                     |
             v                                                     v
+-------------------------------+             +----------------------------------+
| Slack Interactive Card        |             | Embedded React 19 War Room Studio|
| - Root cause & confidence     |             | - Live SSE Incident Stream       |
| - Suspect commit & diff       |             | - Aggregate SRE Health Metrics   |
| - [Confirm Rollback] Button   |             | - Automated Postmortem Generator |
+-------------------------------+             +----------------------------------+
```

## Investigation Pipeline

1. **Webhook Ingestion & Verification**: Webhooks arrive at `/webhooks/pagerduty`, `/webhooks/alertmanager`, `/webhooks/sentry`, `/webhooks/datadog`, or `/webhooks/generic`. Requests undergo HMAC-SHA256 signature or Bearer token validation before being normalized into an `IncidentEvent` with a deterministic SHA256 fingerprint.
2. **Auto-Resolution & MTTR**: When an alert provider signals that an alert has resolved (`is_resolved == true` or `incident.resolved`), IncidentPilot resolves matching active incidents and computes the exact MTTR (Mean Time to Resolution) in seconds.
3. **Deduplication Cooldown**: `Store.FindActiveByFingerprint` checks for ongoing investigations with the same fingerprint inside the configurable `dedup_window_seconds` window. Duplicate alerts increment `alert_count` and log a timeline step without triggering duplicate investigations.
4. **Declarative Service Resolution**: The orchestrator matches the alert's service against `incidentpilot.yaml` service definitions, resolving custom repository paths, GitHub credentials, Loki/Prometheus endpoints, and Slack channels.
5. **Parallel Telemetry Collection**: The engine queries error logs from the incident window ($t \pm 15$ min) and a baseline window (prior 45 min) to calculate error spike ratios. Concurrently, it queries Prometheus rate vectors and fetches recent Git commits and deployment tags.
6. **Stack Trace Parsing & Git Blame**: Universal stack trace parsing extracts call frames across Go, Python, Node.js/TypeScript, Java, and Rust. For lines where crashes occurred, `git blame` pinpoints the author and commit SHA.
7. **AST Proximity & Correlation Scoring**: The correlator scores commits from 0 to 100 based on file path matches, diff hunk line overlaps, blame line attribution, recency decay, and error keyword tokens.
8. **Operational Runbook Matching**: If infrastructure failure patterns are detected (such as container OOMKilled events, database connection pool exhaustion, full disks, or TLS certificate expiry), the engine attaches operational runbook steps from `runbooks.yaml`.
9. **Dispatch & Studio Sync**: The synthesized Incident Brief is dispatched to Slack as a Block Kit interactive message, persisted to SQLite, and broadcast via Server-Sent Events (SSE) to the embedded React 19 War Room Studio.
