# IncidentPilot

IncidentPilot is an autonomous on-call incident responder and log, stack trace, and Git deployment correlator. When an alert arrives from PagerDuty, Prometheus Alertmanager, or Sentry, IncidentPilot pulls error logs from the last 15 minutes, parses stack traces, runs `git blame` on crash lines, inspects recent commits and deployments, matches operational runbooks, and posts an Incident Brief to Slack with an interactive `[Confirm Rollback]` button.

## What it does

1. Ingests webhooks from PagerDuty (V2 and V3), Prometheus Alertmanager (v4), Sentry, or custom JSON monitors, with HMAC-SHA256 and Bearer token verification.
2. Deduplicates repeated alerts by fingerprint inside a configurable cooldown window so alert storms do not spawn duplicate investigations.
3. Automatically marks incidents as resolved and computes MTTR when monitoring systems send resolution webhooks (`status == "resolved"` or `incident.resolved`).
4. Queries error logs from the last 15 minutes and compares them against a prior 45-minute baseline to detect regressions and spike ratios (JSONL files, Grafana Loki, or HTTP log APIs).
5. Inspects recent Git commits, releases, and lines via `git blame` across Go, Python, Node.js/TypeScript, Java, and Rust stack traces.
6. Scores and ranks the top 3 suspect commits by modified file match, diff hunk line proximity, `git blame` line authoring, commit recency, and keyword overlap.
7. Matches operational runbooks from `runbooks.yaml` for infrastructure or resource failures (such as OOMKilled containers, database pool exhaustion, full disks, or TLS expiry).
8. Supports per-service routing via `services.yaml` for teams managing multiple microservices with separate repositories, Slack channels, and rollback workflows.
9. Generates a root-cause brief (deterministically from collected evidence, or via an OpenAI-compatible LLM endpoint when `INCIDENTPILOT_LLM_API_KEY` is set) and sends it to Slack with interactive `[Confirm Rollback]` and `[Dismiss]` buttons.
10. Executes rollbacks via local Git checkout/command, GitHub Actions `workflow_dispatch`, or a signed deployment webhook, while recording an audit trail in SQLite.
11. Serves a live web dashboard with real-time SSE updates, aggregate SRE operational metrics, incident filtering, an on-demand incident simulator, and Markdown postmortem export.

## Quick start

### 1. Install

```bash
git clone https://github.com/alexandrmotologa/incidentpilot.git
cd incidentpilot
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### 2. Run the end-to-end local simulation

The `simulate` command creates a temporary Git repository with `v2.4.1` and `v2.4.2` releases (introducing a nil pointer dereference in `pkg/checkout/checkout.go:114`), writes 15-minute JSONL error logs, fires a PagerDuty V3 webhook, correlates the regression, and executes a real Git rollback to `v2.4.1`:

```bash
incidentpilot simulate
```

### 3. Start the server and web dashboard

```bash
cp .env.example .env
incidentpilot serve --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080` to view the live incident feed, SRE metrics, top suspect commits, operational runbooks, and interactive simulator.

## Interactive Web Simulator

The web dashboard includes a built-in simulation dropdown supporting three scenarios:
- **Go nil pointer (PagerDuty)**: Simulates a checkout panic and checks out previous release `v2.4.1`.
- **Python ZeroDivision (Sentry)**: Simulates an unhandled zero division in billing calculations and correlates recent commits.
- **OOMKilled Runbook (Alertmanager)**: Simulates pod memory eviction (exit code 137) and attaches diagnostic runbook steps.

## API endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Web command center dashboard (SSE live updates) |
| `GET` | `/healthz` | Health check and active provider configuration |
| `GET` | `/api/metrics` | Aggregate SRE operational metrics (incidents, MTTR, hit rate) |
| `POST` | `/api/simulate` | Trigger an on-demand incident simulation (`go_nil_pointer`, `python_checkout_error`, `oom_runbook`) |
| `POST` | `/webhooks/pagerduty` | PagerDuty V2/V3 webhook receiver (`X-PagerDuty-Signature`) |
| `POST` | `/webhooks/alertmanager` | Prometheus Alertmanager v4 receiver (`Authorization: Bearer`) |
| `POST` | `/webhooks/sentry` | Sentry issue/error receiver (`Sentry-Hook-Signature`) |
| `POST` | `/webhooks/generic` | Generic normalized alert receiver |
| `POST` | `/integrations/slack/actions` | Slack interactive button handler (`X-Slack-Signature`) |
| `GET` | `/api/incidents` | List recent incidents with `service`, `severity`, and `status` query filters |
| `GET` | `/api/incidents/{id}` | Get full incident brief, timeline, and rollback history |
| `POST` | `/api/incidents/{id}/rollback` | Trigger rollback from API or dashboard |
| `POST` | `/api/incidents/{id}/dismiss` | Dismiss an incident |
| `GET` | `/api/incidents/{id}/postmortem.md` | Export a Markdown postmortem |
| `GET` | `/api/events` | Server-Sent Events stream for dashboard updates |

## Multi-service routing (`services.yaml`)

Specify custom repositories, Slack channels, and rollback providers per microservice in `services.yaml`:

```yaml
services:
  checkout-api:
    git_provider: local
    local_repo_path: .
    slack_channel: "#oncall-checkout"
    rollback_provider: local_git

  billing-worker:
    git_provider: github
    github_repo: acme-corp/billing-service
    slack_channel: "#oncall-billing"
    rollback_provider: github_workflow
```

## Operational runbooks (`runbooks.yaml`)

Define custom runbook patterns to attach prescriptive diagnostic steps when non-code incidents occur:

```yaml
runbooks:
  - id: redis-oom
    title: Redis Out Of Memory / Eviction Spike
    pattern: "(OOM command not allowed|eviction policy reached|maxmemory reached)"
    steps:
      - "Inspect Redis memory info with `INFO memory`."
      - "Identify key memory consumers using `redis-cli --bigkeys`."
      - "Verify maxmemory-policy setting or raise cluster memory quota."
```

## Configuration

All settings use the `INCIDENTPILOT_` prefix (see `.env.example`):

- `INCIDENTPILOT_LOG_PROVIDER`: `jsonl`, `loki`, or `http`
- `INCIDENTPILOT_GIT_PROVIDER`: `local` or `github`
- `INCIDENTPILOT_ROLLBACK_PROVIDER`: `local_git`, `github_workflow`, or `webhook`
- `INCIDENTPILOT_SERVICES_CONFIG_PATH`: path to `services.yaml` (default: `./services.yaml`)
- `INCIDENTPILOT_RUNBOOKS_CONFIG_PATH`: path to `runbooks.yaml` (default: `./runbooks.yaml`)
- `INCIDENTPILOT_LLM_API_KEY`: optional OpenAI-compatible API key for LLM brief synthesis (falls back to deterministic synthesis when unset)
- `INCIDENTPILOT_SLACK_WEBHOOK_URL` or `INCIDENTPILOT_SLACK_BOT_TOKEN` + `INCIDENTPILOT_SLACK_CHANNEL`: Slack delivery targets

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Webhooks and Security](docs/WEBHOOKS.md)
- [Correlation Scoring](docs/CORRELATION.md)
- [Slack and Rollback Execution](docs/SLACK_AND_ROLLBACK.md)

## Running tests

```bash
pytest -v
```

## License

MIT
