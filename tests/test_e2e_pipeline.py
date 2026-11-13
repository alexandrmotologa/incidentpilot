"""End-to-end API, deduplication, Slack action, and Git rollback tests."""

import hashlib
import hmac
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from incidentpilot.app import create_app
from incidentpilot.config import Settings


def test_full_e2e_incident_and_slack_rollback(tmp_path: Path) -> None:
    repo = tmp_path / "svc"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "SRE"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "sre@example.com"], check=True)

    f = repo / "checkout.go"
    lines = [f"// {i}" for i in range(1, 120)]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "stable release"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "tag", "-a", "v2.4.1", "-m", "v2.4.1"], check=True)

    lines[113] = "panic(\"nil pointer\")"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fast checkout"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "tag", "-a", "v2.4.2", "-m", "v2.4.2"], check=True)

    now = datetime.now(timezone.utc)
    log_file = tmp_path / "logs.jsonl"
    log_file.write_text(
        json.dumps(
            {
                "timestamp": (now - timedelta(minutes=2)).isoformat(),
                "level": "ERROR",
                "service": "checkout-api",
                "message": "panic: nil pointer dereference",
                "stacktrace": "panic: nil pointer dereference\n\t/app/checkout.go:114 +0x10",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    slack_secret = "slack_signing_secret_123"
    settings = Settings(
        db_path=str(tmp_path / "e2e.db"),
        log_provider="jsonl",
        log_file_path=str(log_file),
        git_provider="local",
        local_repo_path=str(repo),
        rollback_provider="local_git",
        slack_signing_secret=slack_secret,
    )
    app = create_app(settings=settings)

    with TestClient(app) as client:
        pd_payload = {
            "event": {
                "event_type": "incident.triggered",
                "occurred_at": now.isoformat(),
                "data": {
                    "id": "PD-100",
                    "title": "Checkout 500s",
                    "urgency": "high",
                    "service": {"summary": "checkout-api"},
                },
            }
        }
        r1 = client.post("/webhooks/pagerduty?sync=true", json=pd_payload)
        assert r1.status_code == 200
        inc_id = r1.json()["incidents"][0]["incident_id"]

        # Duplicate webhook should be deduplicated
        r2 = client.post("/webhooks/pagerduty?sync=true", json=pd_payload)
        assert r2.status_code == 200
        assert r2.json()["incidents"][0]["deduplicated"] is True
        assert r2.json()["incidents"][0]["alert_count"] == 2

        # Inspect detail
        detail = client.get(f"/api/incidents/{inc_id}").json()
        assert detail["status"] == "brief_sent"
        assert detail["brief"]["rollback_target"] == "v2.4.1"
        assert detail["brief"]["confidence"] >= 70.0

        # Postmortem export
        pm = client.get(f"/api/incidents/{inc_id}/postmortem.md")
        assert pm.status_code == 200
        assert "Postmortem: Checkout 500s" in pm.text

        # Trigger Slack [Confirm Rollback] interactive action with valid signature
        action_payload = json.dumps(
            {
                "user": {"username": "alex"},
                "actions": [
                    {"action_id": "confirm_rollback", "value": f"{inc_id}|v2.4.1"}
                ],
            }
        )
        form_body = f"payload={action_payload}".encode("utf-8")
        ts = str(int(time.time()))
        sig = "v0=" + hmac.new(
            slack_secret.encode("utf-8"),
            f"v0:{ts}:".encode("utf-8") + form_body,
            hashlib.sha256,
        ).hexdigest()

        r_slack = client.post(
            "/integrations/slack/actions",
            content=form_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        assert r_slack.status_code == 200
        assert r_slack.json()["rollback_status"] == "succeeded"

        # Verify git repo actually checked out v2.4.1
        head_tag = subprocess.run(
            ["git", "-C", str(repo), "describe", "--tags", "--exact-match", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert head_tag == "v2.4.1"
