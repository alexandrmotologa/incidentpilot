"""Real on-demand incident simulator for CLI and Web Dashboard."""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from incidentpilot.collectors.git import LocalGitProvider
from incidentpilot.collectors.logs import JsonlFileCollector
from incidentpilot.config import Settings
from incidentpilot.models import IncidentRecord
from incidentpilot.orchestrator import IncidentOrchestrator
from incidentpilot.storage import IncidentStore
from incidentpilot.webhooks import (
    parse_alertmanager_webhook,
    parse_pagerduty_webhook,
    parse_sentry_webhook,
)

ScenarioName = Literal["go_nil_pointer", "python_checkout_error", "oom_runbook"]


def _git(repo_dir: Path, *cmd: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *cmd],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


async def run_scenario_simulation(
    store: IncidentStore,
    base_settings: Settings,
    scenario: ScenarioName = "go_nil_pointer",
    broadcast_orch: IncidentOrchestrator | None = None,
) -> IncidentRecord:
    """Create a real temporary Git repo + JSONL logs and run the full investigation pipeline."""
    sim_id = uuid.uuid4().hex[:6]
    base_dir = (
        Path(base_settings.db_path).parent / "sim_repos" / sim_id
        if base_settings.db_path != ":memory:"
        else Path("./data/sim_repos") / sim_id
    )
    repo_dir = base_dir / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    log_path = base_dir / "service.log.jsonl"

    _git(repo_dir, "init", "-b", "main")
    _git(repo_dir, "config", "user.name", "Alexandr Motologa")
    _git(repo_dir, "config", "user.email", "alex@example.com")

    now = datetime.now(timezone.utc)

    if scenario == "python_checkout_error":
        service_name = f"billing-worker-{sim_id}"
        target_file = repo_dir / "app" / "billing.py"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"# line {i}" for i in range(1, 80)]
        lines.extend(
            [
                "def calculate_tax(amount: float, count: int) -> float:",
                "    if count <= 0:",
                "        return 0.0",
                "    return amount / count",
            ]
        )
        target_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _git(repo_dir, "add", ".")
        _git(repo_dir, "commit", "-m", "chore: release v1.8.0")
        _git(repo_dir, "tag", "-a", "v1.8.0", "-m", "Release v1.8.0")

        lines[80] = "    # removed zero guard for batch speed"
        lines[81] = "    return amount / count"
        lines[82] = ""
        target_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _git(repo_dir, "add", ".")
        _git(repo_dir, "commit", "-m", "perf: remove batch count check in billing")
        _git(repo_dir, "tag", "-a", "v1.8.1", "-m", "Release v1.8.1")

        stack = (
            "Traceback (most recent call last):\n"
            '  File "/srv/app/billing.py", line 82, in calculate_tax\n'
            "    return amount / count\n"
            "ZeroDivisionError: division by zero"
        )
        log_entries = [
            {
                "timestamp": (now - timedelta(minutes=4)).isoformat(),
                "level": "ERROR",
                "service": service_name,
                "message": "ZeroDivisionError: division by zero",
                "stacktrace": stack,
            },
            {
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "level": "FATAL",
                "service": service_name,
                "message": "ZeroDivisionError: division by zero",
                "stacktrace": stack,
            },
        ]
        event = parse_sentry_webhook(
            {
                "project_slug": service_name,
                "data": {
                    "event": {
                        "event_id": f"sen-{sim_id}",
                        "title": "ZeroDivisionError: division by zero",
                        "level": "error",
                        "datetime": now.isoformat(),
                        "exception": {
                            "values": [
                                {
                                    "type": "ZeroDivisionError",
                                    "value": "division by zero",
                                    "stacktrace": {
                                        "frames": [
                                            {
                                                "filename": "/srv/app/billing.py",
                                                "lineno": 82,
                                                "function": "calculate_tax",
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                },
            }
        )[0]
    elif scenario == "oom_runbook":
        service_name = f"media-transcoder-{sim_id}"
        readme = repo_dir / "README.md"
        readme.write_text("media-transcoder\n", encoding="utf-8")
        _git(repo_dir, "add", ".")
        _git(repo_dir, "commit", "-m", "chore: release v3.1.0")
        _git(repo_dir, "tag", "-a", "v3.1.0", "-m", "Release v3.1.0")

        log_entries = [
            {
                "timestamp": (now - timedelta(minutes=3)).isoformat(),
                "level": "FATAL",
                "service": service_name,
                "message": "Container terminated with exit code 137 (OOMKilled): memory limit reached",
            },
            {
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "level": "ERROR",
                "service": service_name,
                "message": "Out of memory: cannot allocate memory for worker buffer",
            },
        ]
        event = parse_alertmanager_webhook(
            {
                "alerts": [
                    {
                        "status": "firing",
                        "fingerprint": f"am-{sim_id}",
                        "labels": {
                            "service": service_name,
                            "alertname": "PodOOMKilled",
                            "severity": "critical",
                        },
                        "annotations": {
                            "summary": f"{service_name} OOMKilled (exit code 137)",
                            "description": "Pod exceeded 2Gi memory limit during batch transcode",
                        },
                        "startsAt": now.isoformat(),
                    }
                ]
            }
        )[0]
    else:
        service_name = f"checkout-api-{sim_id}"
        checkout_file = repo_dir / "pkg" / "checkout" / "checkout.go"
        checkout_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"// line {i}" for i in range(1, 110)]
        lines.extend(
            [
                "func Charge(req *ChargeRequest) error {",
                "    if req == nil || req.Customer == nil {",
                '        return errors.New("missing customer")',
                "    }",
                "    return gateway.Submit(req.SafeCustomerID())",
                "}",
            ]
        )
        checkout_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _git(repo_dir, "add", ".")
        _git(repo_dir, "commit", "-m", "chore: release v2.4.1")
        _git(repo_dir, "tag", "-a", "v2.4.1", "-m", "Release v2.4.1")

        lines[110] = "    // removed nil guard for fast-path"
        lines[113] = "    return gateway.Submit(req.Customer.ID)"
        checkout_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _git(repo_dir, "add", ".")
        _git(repo_dir, "commit", "-m", "perf: fast-path checkout customer lookup")
        _git(repo_dir, "tag", "-a", "v2.4.2", "-m", "Release v2.4.2")

        stack = (
            "panic: runtime error: invalid memory address or nil pointer dereference\n"
            "github.com/acme/checkout/pkg/checkout.Charge(0x0)\n"
            "\t/app/pkg/checkout/checkout.go:114 +0x2c"
        )
        log_entries = [
            {
                "timestamp": (now - timedelta(minutes=3)).isoformat(),
                "level": "ERROR",
                "service": service_name,
                "message": "panic: runtime error: invalid memory address or nil pointer dereference",
                "stacktrace": stack,
            },
            {
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "level": "FATAL",
                "service": service_name,
                "message": "panic: runtime error: invalid memory address or nil pointer dereference",
                "stacktrace": stack,
            },
        ]
        event = parse_pagerduty_webhook(
            {
                "event": {
                    "event_type": "incident.triggered",
                    "occurred_at": now.isoformat(),
                    "data": {
                        "id": f"PD-{sim_id}",
                        "number": 901,
                        "title": f"High 5xx rate on {service_name}",
                        "urgency": "high",
                        "service": {"summary": service_name},
                        "body": {"details": "502 Bad Gateway spike after v2.4.2 deploy"},
                    },
                }
            }
        )[0]

    log_path.write_text(
        "\n".join(json.dumps(item) for item in log_entries) + "\n", encoding="utf-8"
    )

    sim_settings = base_settings.model_copy(
        update={
            "log_provider": "jsonl",
            "log_file_path": str(log_path),
            "git_provider": "local",
            "local_repo_path": str(repo_dir),
            "rollback_provider": "local_git",
        }
    )
    sim_orch = IncidentOrchestrator(
        settings=sim_settings,
        store=store,
        log_collector=JsonlFileCollector(str(log_path)),
        git_provider=LocalGitProvider(str(repo_dir)),
    )
    record, _ = await sim_orch.ingest_event(event, wait_for_investigation=True)
    assert record is not None
    if broadcast_orch is not None:
        await broadcast_orch._broadcast("incident_created", record.id)
    return record
