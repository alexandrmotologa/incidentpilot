# IncidentPilot

IncidentPilot is an autonomous on-call incident responder and log, stack trace, and Git deployment correlator. When an alert arrives from PagerDuty, Prometheus Alertmanager, or Sentry, IncidentPilot pulls error logs from the last 15 minutes, parses stack traces, inspects recent commits and deployments, scores the most likely regression, and posts an Incident Brief to Slack with a `[Confirm Rollback]` button.

## What it does

1. Ingests webhooks from PagerDuty (V2 and V3), Prometheus Alertmanager (v4), Sentry, or custom JSON monitors, with HMAC-SHA256 and Bearer token verification.
2. Deduplicates repeated alerts by fingerprint inside a configurable cooldown window so alert storms do not spawn duplicate investigations.
3. Queries error logs from the last 15 minutes (JSONL files, Grafana Loki, or HTTP log APIs) and recent Git commits and releases (local Git repositories or the GitHub REST API) in parallel.
4. Parses stack traces across Go, Python, Node.js/TypeScript, Java, and Rust, then scores commits by modified file match, diff hunk line proximity, commit recency, and error keyword overlap.
5. Generates a root-cause brief (deterministically from collected evidence, or via an OpenAI-compatible LLM endpoint when `INCIDENTPILOT_LLM_API_KEY` is set) and sends it to Slack with interactive `[Confirm Rollback]` and `[Dismiss]` buttons.
6. Executes rollbacks via local Git checkout/command, GitHub Actions `workflow_dispatch`, or a signed deployment webhook, while recording an audit trail in SQLite and serving a live web dashboard with Markdown postmortem export.

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

Open `http://localhost:8080` to view the live incident feed, stack traces, commit diffs, investigation timeline, and rollback controls.

## API endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Web dashboard (SSE live updates) |
| `GET` | `/healthz` | Health check and active provider configuration |
| `POST` | `/webhooks/pagerduty` | PagerDuty V2/V3 webhook receiver (`X-PagerDuty-Signature`) |
| `POST` | `/webhooks/alertmanager` | Prometheus Alertmanager v4 receiver (`Authorization: Bearer`) |
| `POST` | `/webhooks/sentry` | Sentry issue/error receiver (`Sentry-Hook-Signature`) |
| `POST` | `/webhooks/generic` | Generic normalized alert receiver |
| `POST` | `/integrations/slack/actions` | Slack interactive button handler (`X-Slack-Signature`) |
| `GET` | `/api/incidents` | List recent incidents |
| `GET` | `/api/incidents/{id}` | Get full incident brief, timeline, and rollback history |
| `POST` | `/api/incidents/{id}/rollback` | Trigger rollback from API or dashboard |
| `POST` | `/api/incidents/{id}/dismiss` | Dismiss an incident |
| `GET` | `/api/incidents/{id}/postmortem.md` | Export a Markdown postmortem |
| `GET` | `/api/events` | Server-Sent Events stream for dashboard updates |

## Configuration

All settings use the `INCIDENTPILOT_` prefix (see `.env.example`):

- `INCIDENTPILOT_LOG_PROVIDER`: `jsonl`, `loki`, or `http`
- `INCIDENTPILOT_GIT_PROVIDER`: `local` or `github`
- `INCIDENTPILOT_ROLLBACK_PROVIDER`: `local_git`, `github_workflow`, or `webhook`
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
