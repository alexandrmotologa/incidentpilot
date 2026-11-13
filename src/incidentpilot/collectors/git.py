"""Git commit, diff, and deployment collectors (Local Git & GitHub REST API)."""

from __future__ import annotations

import asyncio
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

import httpx

from incidentpilot.config import Settings
from incidentpilot.models import CommitInfo, DeploymentInfo, FileDiff

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def parse_changed_line_ranges(patch: str) -> list[tuple[int, int]]:
    """Extract added/modified line intervals from a unified diff patch."""
    ranges: list[tuple[int, int]] = []
    for line in patch.splitlines():
        match = _HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group("start"))
        count = int(match.group("count") or "1")
        end = start + max(count - 1, 0)
        ranges.append((start, end))
    return ranges


class GitProvider(Protocol):
    """Interface for retrieving recent commits and deployments."""

    async def fetch_recent_commits(
        self, since: datetime, limit: int = 25
    ) -> list[CommitInfo]: ...

    async def fetch_recent_deployments(
        self, environment: str = "production", limit: int = 10
    ) -> list[DeploymentInfo]: ...


class LocalGitProvider:
    """Inspects a real local Git repository via git CLI."""

    def __init__(self, repo_path: str) -> None:
        self.repo_path = str(Path(repo_path).resolve())

    def _run_git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", self.repo_path, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode != 0:
            return ""
        return proc.stdout

    def _fetch_commits_sync(self, since: datetime, limit: int) -> list[CommitInfo]:
        since_iso = since.astimezone(timezone.utc).isoformat()
        log_out = self._run_git(
            "log",
            f"-n{limit}",
            f"--since={since_iso}",
            "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%s",
        )
        if not log_out.strip():
            # Fallback to latest commits if none fall strictly inside the window
            log_out = self._run_git(
                "log",
                f"-n{min(limit, 10)}",
                "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%s",
            )

        commits: list[CommitInfo] = []
        for row in log_out.splitlines():
            parts = row.split("\x1f")
            if len(parts) < 6:
                continue
            sha, short_sha, author, email, ts_raw, message = parts[:6]
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = datetime.now(timezone.utc)

            diff_text = self._run_git("show", "--unified=3", "--no-color", "--format=", sha)
            files = self._parse_git_show_diff(diff_text)
            commits.append(
                CommitInfo(
                    sha=sha,
                    short_sha=short_sha,
                    author=author,
                    email=email,
                    message=message,
                    timestamp=ts,
                    files=files,
                )
            )
        return commits

    @staticmethod
    def _parse_git_show_diff(diff_text: str) -> list[FileDiff]:
        files: list[FileDiff] = []
        current_path: str | None = None
        patch_lines: list[str] = []
        additions = 0
        deletions = 0

        def flush() -> None:
            if current_path is not None:
                patch = "\n".join(patch_lines)
                files.append(
                    FileDiff(
                        path=current_path,
                        additions=additions,
                        deletions=deletions,
                        patch=patch,
                        changed_line_ranges=parse_changed_line_ranges(patch),
                    )
                )

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                flush()
                current_path = None
                patch_lines = []
                additions = 0
                deletions = 0
                parts = line.split(" b/")
                if len(parts) == 2:
                    current_path = parts[1].strip()
            elif current_path is not None:
                if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("index "):
                    continue
                if line.startswith("+") and not line.startswith("+++"):
                    additions += 1
                elif line.startswith("-") and not line.startswith("---"):
                    deletions += 1
                patch_lines.append(line)

        flush()
        return files

    def _fetch_deployments_sync(self, environment: str, limit: int) -> list[DeploymentInfo]:
        # Use annotated/lightweight tags as release deployment markers
        out = self._run_git(
            "for-each-ref",
            f"--count={limit}",
            "--sort=-creatordate",
            "--sort=-v:refname",
            "--format=%(refname:short)|%(*objectname:short)|%(objectname:short)|%(creatordate:iso-strict)",
            "refs/tags",
        )
        deployments: list[DeploymentInfo] = []
        for idx, line in enumerate(out.splitlines()):
            parts = line.split("|")
            if len(parts) < 4:
                continue
            tag, deref_sha, obj_sha, ts_raw = parts[:4]
            commit_sha = deref_sha or obj_sha
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = datetime.now(timezone.utc)
            deployments.append(
                DeploymentInfo(
                    id=f"tag-{idx}-{tag}",
                    version=tag,
                    tag=tag,
                    commit_sha=commit_sha,
                    environment=environment,
                    created_at=ts,
                    status="success",
                )
            )
        return deployments

    async def fetch_recent_commits(
        self, since: datetime, limit: int = 25
    ) -> list[CommitInfo]:
        return await asyncio.to_thread(self._fetch_commits_sync, since, limit)

    async def fetch_recent_deployments(
        self, environment: str = "production", limit: int = 10
    ) -> list[DeploymentInfo]:
        return await asyncio.to_thread(self._fetch_deployments_sync, environment, limit)


class GitHubGitProvider:
    """Fetches commits, diffs, deployments, and releases via GitHub REST API."""

    def __init__(self, repo: str, token: str = "", timeout: float = 15.0) -> None:
        self.repo = repo.strip("/")
        self.token = token
        self.timeout = timeout
        self.base_url = "https://api.github.com"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def fetch_recent_commits(
        self, since: datetime, limit: int = 25
    ) -> list[CommitInfo]:
        if not self.repo:
            return []
        params = {
            "since": since.astimezone(timezone.utc).isoformat(),
            "per_page": min(limit, 30),
        }
        async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers()) as client:
            resp = await client.get(f"{self.base_url}/repos/{self.repo}/commits", params=params)
            resp.raise_for_status()
            commit_summaries = resp.json()

            # Fetch detailed diffs concurrently (cap to top 10 to stay well under 60s)
            top_shas = [c["sha"] for c in commit_summaries[:10] if "sha" in c]
            detail_tasks = [
                client.get(f"{self.base_url}/repos/{self.repo}/commits/{sha}")
                for sha in top_shas
            ]
            detail_responses = await asyncio.gather(*detail_tasks, return_exceptions=True)

        commits: list[CommitInfo] = []
        for summary, detail_res in zip(commit_summaries[:10], detail_responses):
            commit_meta = summary.get("commit") or {}
            author_meta = commit_meta.get("author") or {}
            ts_raw = author_meta.get("date") or datetime.now(timezone.utc).isoformat()
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)

            files: list[FileDiff] = []
            if isinstance(detail_res, httpx.Response) and detail_res.status_code == 200:
                detail_json = detail_res.json()
                for f in detail_json.get("files") or []:
                    patch = f.get("patch") or ""
                    files.append(
                        FileDiff(
                            path=f.get("filename", ""),
                            additions=int(f.get("additions", 0)),
                            deletions=int(f.get("deletions", 0)),
                            patch=patch,
                            changed_line_ranges=parse_changed_line_ranges(patch),
                        )
                    )

            sha = summary["sha"]
            commits.append(
                CommitInfo(
                    sha=sha,
                    short_sha=sha[:7],
                    author=str(author_meta.get("name") or "unknown"),
                    email=str(author_meta.get("email") or ""),
                    message=str(commit_meta.get("message") or "").splitlines()[0],
                    timestamp=ts,
                    files=files,
                    url=str(summary.get("html_url") or ""),
                )
            )
        return commits

    async def fetch_recent_deployments(
        self, environment: str = "production", limit: int = 10
    ) -> list[DeploymentInfo]:
        if not self.repo:
            return []
        deployments: list[DeploymentInfo] = []
        async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers()) as client:
            resp = await client.get(
                f"{self.base_url}/repos/{self.repo}/releases",
                params={"per_page": limit},
            )
            if resp.status_code == 200:
                for rel in resp.json():
                    tag = str(rel.get("tag_name") or "")
                    ts_raw = rel.get("published_at") or rel.get("created_at") or ""
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    except ValueError:
                        ts = datetime.now(timezone.utc)
                    deployments.append(
                        DeploymentInfo(
                            id=str(rel.get("id", tag)),
                            version=tag,
                            tag=tag,
                            commit_sha=str(rel.get("target_commitish") or ""),
                            environment=environment,
                            created_at=ts,
                            status="success",
                        )
                    )
        return deployments


def build_git_provider(settings: Settings) -> GitProvider:
    """Instantiate the configured Git & deployment provider."""
    if settings.git_provider == "github":
        return GitHubGitProvider(repo=settings.github_repo, token=settings.github_token)
    return LocalGitProvider(repo_path=settings.local_repo_path)


def default_git_since(settings: Settings) -> datetime:
    """Compute lookback timestamp for commit queries."""
    return datetime.now(timezone.utc) - timedelta(hours=settings.git_lookback_hours)
