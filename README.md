# IncidentPilot

IncidentPilot is an autonomous on-call incident responder and log, stack trace, and Git deployment correlator. When an alert arrives from PagerDuty, Prometheus Alertmanager, Sentry, or Datadog, IncidentPilot pulls error logs from the last 15 minutes, parses stack traces, attributes crash lines with `git blame`, inspects recent commits and deployments, matches operational runbooks, and posts an Incident Brief to Slack with an interactive `[Confirm Rollback]` button.

Packaged as a single Go binary under 25MB RAM with an embedded React 19 War Room Studio and a pure-Go SQLite persistence layer (`modernc.org/sqlite`, zero CGO runtime dependencies).

## Core Capabilities

1. **Multi-Source Webhook Ingestion**: Ingests alerts from PagerDuty (V2/V3), Prometheus Alertmanager (v4), Sentry, Datadog, or custom JSON webhooks with HMAC-SHA256 signature and Bearer token verification.
2. **Deduplication & Cooldown**: Deduplicates repeating alerts by deterministic SHA256 fingerprint within a configurable window (default 300s) to prevent alert storm duplicate runs.
3. **Automated Resolution & MTTR**: Resolves matching active incidents automatically upon receiving resolution payloads and records Mean Time to Resolution (MTTR) metrics.
4. **Telemetry & Log Extraction**: Fetches error logs from the incident window (last 15 minutes) and compares them against a 45-minute baseline to detect regressions and calculate spike ratios across JSONL files or Grafana Loki.
5. **Universal Stack Trace Parsing**: Parses call frames across Go, Python, Node.js/TypeScript, Java, and Rust.
6. **AST Proximity & Git Blame Correlation**: Scores candidate commits (0 to 100) using modified file matching (45 pts), diff hunk line proximity (25 pts), `git blame` author attribution (20 pts), recency decay (15 pts), and error keyword tokens (15 pts).
7. **Operational Runbook Matching**: Detects infrastructure failures (OOMKilled pods, database connection pool exhaustion, full disks, TLS certificate expiry, 429 upstream rate limits) and attaches prescriptive diagnostic steps from `runbooks.yaml`.
8. **Declarative Service Configuration**: Configured via `incidentpilot.yaml` with environment variable expansion (`${VAR}`) for multi-service environments.
9. **Slack Block Kit Dispatcher**: Formats interactive Slack briefs with collapsible evidence and `[Confirm Rollback]` / `[Dismiss]` buttons.
10. **Slack Thread Assistant Co-Pilot**: Responds in-thread to engineering queries (`@incidentpilot diff`, `@incidentpilot logs`, `@incidentpilot status`, `@incidentpilot postmortem`).
11. **Two-Way PagerDuty & Sentry Sync**: Auto-acknowledges PagerDuty alerts during active investigation and publishes diagnostic work notes with suspect commit links.
12. **Multi-Provider Rollback Execution**: Executes rollbacks via local Git checkout/command, GitHub Actions workflow dispatch, or signed deployment webhooks with complete audit history.
13. **Closed-Loop Health Verification**: Automatically monitors post-rollback error logs and Prometheus metrics during a verification window to confirm system recovery (`verified_healthy`) or escalate if errors persist (`escalated`).
14. **Declarative Auto-Rollback Guardrails**: Configurable policy checks (`environments`, `min_confidence`, `min_spike_ratio`, `max_rollback_age_hours`) for safe, hands-free remediation.
15. **Direct GitHub Issue Postmortem Exporter**: Exports incident timelines, MTTR, and root cause analysis directly to GitHub Issues with a single click.
16. **Built-in SRE Benchmark & Chaos Suite**: CLI benchmark runner (`incidentpilot bench`) measuring correlation precision, recall, and latency across synthetic incident vectors.
17. **Minimalist Terminal Cockpit**: Pure-Go ANSI terminal UI (`incidentpilot top`) for SSH bastions and terminal on-call sessions.
18. **Embedded React 19 War Room Studio**: High-density operational cockpit served directly from the single binary with real-time SSE stream, live metrics bar, commit diff viewer, runbook viewer, and health verification indicators.

## Quick Start

### 1. Build from Source

Requirements: Go 1.24+ and Node.js 20+ (for building the embedded UI).

```bash
git clone https://github.com/alexandrmotologa/incidentpilot.git
cd incidentpilot

# Build embedded React 19 UI
cd ui
npm ci
npm run build
cd ..

# Build single binary
go build -o incidentpilot.exe ./cmd/incidentpilot
```

Or build with Docker:

```bash
docker build -t incidentpilot:latest .
```

### 2. Run Local End-to-End Simulation

The `simulate` command creates a temporary Git repository with releases `v2.4.1` and `v2.4.2` (introducing a nil pointer dereference in `pkg/checkout/checkout.go:114`), generates 15-minute JSONL error logs, triggers an alert investigation, correlates the suspect commit, and executes a verified Git rollback to `v2.4.1`:

```bash
./incidentpilot simulate
```

### 3. Run the SRE Benchmark Suite

```bash
./incidentpilot bench
```

### 4. Start the Daemon and War Room Studio

```bash
cp incidentpilot.example.yaml incidentpilot.yaml
./incidentpilot serve --config ./incidentpilot.yaml --port 8080
```

Open `http://localhost:8080` to access the embedded React 19 War Room Studio.

## CLI Usage

```text
IncidentPilot: Autonomous On-Call Incident Responder & Telemetry Correlator

Usage:
  incidentpilot [command] [flags]

Commands:
  serve       Start the webhook receiver and embedded War Room Studio
  replay      Re-investigate a past incident from stored telemetry or logs
  list        List recent incidents and their status
  simulate    Run an end-to-end local incident simulation scenario
  bench       Run the automated SRE correlation benchmark suite
  top         Launch the interactive terminal dashboard
```

### Examples

```bash
# Start server on custom port
incidentpilot serve --config incidentpilot.yaml --port 8080

# Launch terminal cockpit
incidentpilot top

# Run terminal cockpit snapshot once
incidentpilot top --once

# Run the correlation benchmark suite
incidentpilot bench

# List active incidents
incidentpilot list --status investigating

# Replay an investigation for an existing incident
incidentpilot replay --id inc-8f2a1c99

# Run a specific simulation scenario
incidentpilot simulate --scenario go_nil_pointer
incidentpilot simulate --scenario python_checkout_error
incidentpilot simulate --scenario oom_runbook
```

## Declarative Service Configuration (`incidentpilot.yaml`)

```yaml
version: "1"
host: "0.0.0.0"
port: 8080
database_path: "./data/incidentpilot.db"
dedup_window_seconds: 300
investigation_timeout_seconds: 60
log_window_minutes: 15
git_lookback_hours: 24
health_check_duration_seconds: 30

# Webhook authentication secrets
pagerduty_webhook_secret: "${PAGERDUTY_WEBHOOK_SECRET}"
pagerduty_api_token: "${PAGERDUTY_API_TOKEN}"
sentry_client_secret: "${SENTRY_CLIENT_SECRET}"
sentry_auth_token: "${SENTRY_AUTH_TOKEN}"
alertmanager_bearer_token: "${ALERTMANAGER_BEARER_TOKEN}"
datadog_webhook_token: "${DATADOG_WEBHOOK_TOKEN}"
github_token: "${GITHUB_TOKEN}"
github_repo: "alexandrmotologa/incidentpilot"

# Monitored microservices
services:
  - name: "checkout-api"
    repo: "alexandrmotologa/incidentpilot"
    local_repo_path: "."
    github_token: "${GITHUB_TOKEN}"
    slack_channel: "#sre-war-room"
    observability:
      loki_url: "http://localhost:3100"
      prometheus_url: "http://localhost:9090"
      error_metric_query: 'sum(rate(http_requests_total{status=~"5.."}[2m]))'
      log_file_path: "./data/service.log.jsonl"
    mitigation:
      allow_auto_rollback: false
      auto_rollback:
        enabled: true
        environments: ["staging", "canary"]
        min_confidence: 90.0
        min_spike_ratio: 5.0
        max_rollback_age_hours: 48
      rollback_provider: "local_git"
      rollback_command: ""

notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    bot_token: "${SLACK_BOT_TOKEN}"
    channel: "#sre-war-room"
    signing_secret: "${SLACK_SIGNING_SECRET}"

runbooks_path: "./runbooks.yaml"
```

## API Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Embedded React 19 War Room Studio |
| `GET` | `/healthz` | System health check and runtime status |
| `GET` | `/api/metrics` | SRE operational metrics (Total incidents, MTTR, hit rate) |
| `GET` | `/api/incidents` | List incidents with `service`, `severity`, and `status` query filters |
| `GET` | `/api/incidents/{id}` | Full incident record, brief, timeline, and rollback history |
| `POST` | `/api/incidents/{id}/rollback` | Trigger verified rollback for an incident |
| `POST` | `/api/incidents/{id}/dismiss` | Dismiss an incident |
| `POST` | `/api/incidents/{id}/export-github` | Export postmortem to a GitHub Issue |
| `GET` | `/api/incidents/{id}/postmortem.md` | Download incident postmortem in Markdown format |
| `POST` | `/api/simulate` | Trigger on-demand simulation (`go_nil_pointer`, `python_checkout_error`, `oom_runbook`) |
| `GET` | `/api/events` | Server-Sent Events (SSE) stream for live updates |
| `POST` | `/webhooks/pagerduty` | PagerDuty V2/V3 webhook receiver (`X-PagerDuty-Signature`) |
| `POST` | `/webhooks/alertmanager` | Prometheus Alertmanager v4 receiver (`Authorization: Bearer`) |
| `POST` | `/webhooks/sentry` | Sentry issue/error webhook receiver (`Sentry-Hook-Signature`) |
| `POST` | `/webhooks/datadog` | Datadog webhook receiver (`DD-WEBHOOK-TOKEN`) |
| `POST` | `/webhooks/generic` | Normalized JSON alert receiver |
| `POST` | `/integrations/slack/actions` | Slack interactivity callback receiver (`X-Slack-Signature`) |
| `POST` | `/integrations/slack/events` | Slack Event Subscription receiver for in-thread assistant |

## License

MIT License. See [LICENSE](LICENSE) for details.
