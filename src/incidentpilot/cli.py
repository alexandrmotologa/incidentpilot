"""Command-line interface for IncidentPilot."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn

from incidentpilot.app import create_app
from incidentpilot.config import Settings, get_settings
from incidentpilot.orchestrator import IncidentOrchestrator
from incidentpilot.storage import IncidentStore
from incidentpilot.webhooks import parse_pagerduty_webhook


def _cmd_serve(args: argparse.Namespace) -> None:
    settings = get_settings()
    app = create_app(settings=settings)
    uvicorn.run(
        app,
        host=args.host or settings.host,
        port=args.port or settings.port,
        log_level="info",
    )


async def _run_simulation() -> None:
    """Spin up a real temporary Git repo + 15-minute JSONL logs and run the full pipeline."""
    with tempfile.TemporaryDirectory(prefix="incidentpilot-sim-") as tmp:
        root = Path(tmp)
        repo_dir = root / "checkout-service"
        repo_dir.mkdir()

        def git(*cmd: str) -> str:
            proc = subprocess.run(
                ["git", "-C", str(repo_dir), *cmd],
                capture_output=True,
                text=True,
                check=True,
            )
            return proc.stdout.strip()

        git("init", "-b", "main")
        git("config", "user.name", "Alexandr Motologa")
        git("config", "user.email", "alex@example.com")

        # Stable commit v2.4.1
        checkout_file = repo_dir / "pkg" / "checkout" / "checkout.go"
        checkout_file.parent.mkdir(parents=True)
        lines = [f"// line {i}" for i in range(1, 110)]
        lines.extend(
            [
                "func Charge(req *ChargeRequest) error {",
                "    if req == nil || req.Customer == nil {",
                '        return errors.New("missing customer")',
                "    }",
                "    return gateway.Submit(req.Customer.ID)",
                "}",
            ]
        )
        checkout_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        git("add", ".")
        git("commit", "-m", "chore: release v2.4.1")
        git("tag", "-a", "v2.4.1", "-m", "Release v2.4.1")

        # Regression commit introducing nil pointer dereference at line 114
        lines[110] = "    // removed nil guard for fast-path"
        lines[113] = "    return gateway.Submit(req.Customer.ID)"
        checkout_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        git("add", ".")
        git("commit", "-m", "perf: fast-path checkout customer lookup")
        bad_sha = git("rev-parse", "--short", "HEAD")
        git("tag", "-a", "v2.4.2", "-m", "Release v2.4.2")

        # Write real JSONL logs for the last 15 minutes
        log_path = root / "service.log.jsonl"
        now = datetime.now(timezone.utc)
        stack = (
            "panic: runtime error: invalid memory address or nil pointer dereference\n"
            "github.com/acme/checkout/pkg/checkout.Charge(0x0)\n"
            "\t/app/pkg/checkout/checkout.go:114 +0x2c"
        )
        log_records = [
            {
                "timestamp": (now - timedelta(minutes=3)).isoformat(),
                "level": "ERROR",
                "service": "checkout-api",
                "message": "panic: runtime error: invalid memory address or nil pointer dereference",
                "stacktrace": stack,
            },
            {
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "level": "FATAL",
                "service": "checkout-api",
                "message": "panic: runtime error: invalid memory address or nil pointer dereference",
                "stacktrace": stack,
            },
        ]
        log_path.write_text(
            "\n".join(json.dumps(item) for item in log_records) + "\n", encoding="utf-8"
        )

        settings = Settings(
            db_path=str(root / "sim.db"),
            log_provider="jsonl",
            log_file_path=str(log_path),
            git_provider="local",
            local_repo_path=str(repo_dir),
            rollback_provider="local_git",
        )
        store = IncidentStore(settings.db_path)
        orch = IncidentOrchestrator(settings=settings, store=store)

        pd_payload = {
            "event": {
                "event_type": "incident.triggered",
                "occurred_at": now.isoformat(),
                "data": {
                    "id": "PD-SIM-901",
                    "number": 901,
                    "title": "High 5xx rate on checkout-api",
                    "urgency": "high",
                    "service": {"summary": "checkout-api"},
                    "body": {"details": "502 Bad Gateway spike after v2.4.2 deploy"},
                },
            }
        }
        events = parse_pagerduty_webhook(pd_payload)
        record, _ = await orch.ingest_event(events[0], wait_for_investigation=True)
        print(f"Incident ID: {record.id}")
        print(f"Suspect SHA: {bad_sha}")
        if record.brief:
            print(f"Probable Cause: {record.brief.probable_cause}")
            print(f"Recommendation: {record.brief.recommendation}")
            print(f"Confidence: {record.brief.confidence:.1f}%")
            print(f"Duration: {record.brief.investigation_duration_ms} ms")

        # Execute rollback
        updated, rb = await orch.trigger_rollback(record.id, requested_by="cli-sim")
        print(f"Rollback Status: {rb.status} -> {rb.output}")
        print(f"Final Incident Status: {updated.status.value}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="incidentpilot", description="IncidentPilot CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Start the IncidentPilot webhook & dashboard server")
    serve_p.add_argument("--host", default=None)
    serve_p.add_argument("--port", type=int, default=None)

    sub.add_parser("simulate", help="Run an end-to-end local Git + JSONL + PagerDuty simulation")

    args = parser.parse_args()
    if args.command == "serve":
        _cmd_serve(args)
    elif args.command == "simulate":
        asyncio.run(_run_simulation())
