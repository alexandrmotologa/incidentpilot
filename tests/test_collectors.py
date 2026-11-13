"""Tests for JSONL log collector and LocalGitProvider."""

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incidentpilot.collectors.git import LocalGitProvider
from incidentpilot.collectors.logs import JsonlFileCollector


async def test_jsonl_collector_filters_window_and_service(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log_file = tmp_path / "app.jsonl"
    rows = [
        {"timestamp": (now - timedelta(minutes=30)).isoformat(), "level": "ERROR", "service": "checkout", "message": "too old"},
        {"timestamp": (now - timedelta(minutes=5)).isoformat(), "level": "INFO", "service": "checkout", "message": "info ignored"},
        {"timestamp": (now - timedelta(minutes=4)).isoformat(), "level": "ERROR", "service": "other", "message": "wrong service"},
        {"timestamp": (now - timedelta(minutes=2)).isoformat(), "level": "ERROR", "service": "checkout", "message": "nil pointer"},
    ]
    log_file.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    collector = JsonlFileCollector(str(log_file))
    entries = await collector.fetch_error_logs(
        service="checkout",
        since=now - timedelta(minutes=15),
        until=now + timedelta(minutes=1),
    )
    assert len(entries) == 1
    assert entries[0].message == "nil pointer"


async def test_local_git_provider_reads_commits_diffs_and_tags(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@example.com"], check=True)

    target = repo / "checkout.go"
    target.write_text("package main\nfunc a() {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "tag", "-a", "v1.0.0", "-m", "v1.0.0"], check=True)

    target.write_text("package main\nfunc a() { panic(\"boom\") }\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "break checkout"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "tag", "-a", "v1.0.1", "-m", "v1.0.1"], check=True)

    provider = LocalGitProvider(str(repo))
    commits = await provider.fetch_recent_commits(datetime.now(timezone.utc) - timedelta(hours=1))
    assert len(commits) == 2
    assert commits[0].message == "break checkout"
    assert commits[0].files[0].path == "checkout.go"
    assert len(commits[0].files[0].changed_line_ranges) >= 1

    deployments = await provider.fetch_recent_deployments()
    assert [d.version for d in deployments][:2] == ["v1.0.1", "v1.0.0"]
