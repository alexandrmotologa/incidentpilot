"""Real rollback executor supporting Local Git, GitHub Workflows, and Signed Webhooks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import subprocess
import uuid
from pathlib import Path

import httpx

from incidentpilot.config import Settings
from incidentpilot.models import IncidentRecord, RollbackRecord


class RollbackExecutor:
    """Executes rollbacks against the configured deployment target."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def execute(
        self,
        record: IncidentRecord,
        target_version: str,
        requested_by: str = "oncall-engineer",
    ) -> RollbackRecord:
        """Run the configured rollback strategy and return an audit record."""
        rollback_id = f"rb-{uuid.uuid4().hex[:10]}"
        provider = self.settings.rollback_provider

        try:
            if provider == "github_workflow":
                output = await self._run_github_workflow(record, target_version)
            elif provider == "webhook":
                output = await self._run_webhook(record, target_version, requested_by)
            else:
                output = await asyncio.to_thread(
                    self._run_local_git_or_command, record, target_version
                )
            return RollbackRecord(
                id=rollback_id,
                incident_id=record.id,
                target_version=target_version,
                provider=provider,
                status="succeeded",
                requested_by=requested_by,
                output=output,
            )
        except Exception as exc:
            return RollbackRecord(
                id=rollback_id,
                incident_id=record.id,
                target_version=target_version,
                provider=provider,
                status="failed",
                requested_by=requested_by,
                error=str(exc),
            )

    def _run_local_git_or_command(self, record: IncidentRecord, target_version: str) -> str:
        repo_path = str(Path(self.settings.local_repo_path).resolve())
        env = os.environ.copy()
        env["INCIDENTPILOT_INCIDENT_ID"] = record.id
        env["INCIDENTPILOT_SERVICE"] = record.event.service
        env["INCIDENTPILOT_TARGET_VERSION"] = target_version

        if self.settings.rollback_command:
            proc = subprocess.run(
                self.settings.rollback_command,
                cwd=repo_path,
                env=env,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or f"Command exited with {proc.returncode}")
            return proc.stdout.strip() or f"Executed rollback command for {target_version}"

        # Verify ref exists in local git repo, then check out target ref safely
        verify = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "--verify", target_version],
            capture_output=True,
            text=True,
            check=False,
        )
        if verify.returncode != 0:
            raise RuntimeError(f"Git ref '{target_version}' not found in {repo_path}")

        target_sha = verify.stdout.strip()
        checkout = subprocess.run(
            ["git", "-C", repo_path, "checkout", "--detach", target_version],
            capture_output=True,
            text=True,
            check=False,
        )
        if checkout.returncode != 0:
            raise RuntimeError(checkout.stderr.strip() or "git checkout failed")

        return f"Checked out {target_version} ({target_sha[:7]}) in {repo_path}"

    async def _run_github_workflow(self, record: IncidentRecord, target_version: str) -> str:
        if not self.settings.github_repo or not self.settings.github_token:
            raise RuntimeError("INCIDENTPILOT_GITHUB_REPO and INCIDENTPILOT_GITHUB_TOKEN are required")
        url = (
            f"https://api.github.com/repos/{self.settings.github_repo}/actions/"
            f"workflows/{self.settings.github_rollback_workflow}/dispatches"
        )
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {self.settings.github_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "ref": "main",
                    "inputs": {
                        "version": target_version,
                        "service": record.event.service,
                        "incident_id": record.id,
                    },
                },
            )
            resp.raise_for_status()
        return f"Dispatched GitHub workflow {self.settings.github_rollback_workflow} for {target_version}"

    async def _run_webhook(
        self, record: IncidentRecord, target_version: str, requested_by: str
    ) -> str:
        if not self.settings.rollback_webhook_url:
            raise RuntimeError("INCIDENTPILOT_ROLLBACK_WEBHOOK_URL is not configured")
        payload = {
            "incident_id": record.id,
            "service": record.event.service,
            "environment": record.event.environment,
            "target_version": target_version,
            "requested_by": requested_by,
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.settings.rollback_webhook_secret:
            sig = hmac.new(
                self.settings.rollback_webhook_secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            headers["X-IncidentPilot-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(self.settings.rollback_webhook_url, content=body, headers=headers)
            resp.raise_for_status()
        return f"Webhook rollback accepted ({resp.status_code}) for {target_version}"
