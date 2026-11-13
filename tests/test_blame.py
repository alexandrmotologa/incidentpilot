"""Tests for git blame extraction and score boosting."""

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incidentpilot.collectors.git import LocalGitProvider
from incidentpilot.correlator.engine import correlate_incident
from incidentpilot.models import (
    AlertSource,
    IncidentEvent,
    ParsedStackTrace,
    StackFrame,
)


async def test_git_blame_line_and_score_boost(tmp_path: Path) -> None:
    repo = tmp_path / "blame_repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@example.com"], check=True)

    file_p = repo / "pkg" / "calc.py"
    file_p.parent.mkdir(parents=True, exist_ok=True)
    file_p.write_text("def run():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)

    # Culprit commit modifies line 2
    file_p.write_text("def run():\n    return 1 / 0\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "broken division"], check=True, capture_output=True)
    bad_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    provider = LocalGitProvider(str(repo))
    blamed_sha = await provider.blame_line("/app/pkg/calc.py", line=2)
    assert blamed_sha is not None
    assert blamed_sha.startswith(bad_sha[:7])

    now = datetime.now(timezone.utc)
    event = IncidentEvent(
        source=AlertSource.GENERIC,
        external_id="1",
        fingerprint="fp-calc",
        service="calc-service",
        title="ZeroDivisionError",
        triggered_at=now,
    )
    st = ParsedStackTrace(
        error_type="ZeroDivisionError",
        error_message="division by zero",
        language="python",
        frames=[StackFrame(file="/app/pkg/calc.py", line=2, language="python")],
    )
    commits = await provider.fetch_recent_commits(now - timedelta(hours=1))
    deployments = await provider.fetch_recent_deployments()

    candidates = correlate_incident(
        event,
        [],
        [st],
        commits,
        deployments,
        blame_shas={blamed_sha},
    )
    assert len(candidates) >= 1
    top = candidates[0]
    assert top.commit.sha == bad_sha
    assert any("git blame confirms" in reason for reason in top.reasons)
