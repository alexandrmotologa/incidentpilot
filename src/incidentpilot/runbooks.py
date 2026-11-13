"""Operational runbook matcher for infrastructure and resource incidents."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from incidentpilot.models import IncidentEvent, LogEntry, RunbookMatch

DEFAULT_RUNBOOKS: list[dict[str, object]] = [
    {
        "id": "oom-killed",
        "title": "Container OOMKilled / Memory Exhaustion",
        "pattern": r"(oomkilled|out of memory|cannot allocate memory|exit code 137|memory limit)",
        "steps": [
            "Check pod memory usage and recent heap allocation changes (`kubectl top pods`).",
            "Inspect memory limits in deployment manifests and compare against p99 RSS.",
            "Capture a heap profile before restarting or scaling replicas horizontally.",
        ],
    },
    {
        "id": "db-pool-exhausted",
        "title": "Database Connection Pool Exhaustion",
        "pattern": r"(connection pool|too many connections|remaining connection slots|pool timeout|acquire connection)",
        "steps": [
            "Check active vs idle database connections (`pg_stat_activity` or pool metrics).",
            "Look for unclosed transactions or long-running queries blocking pool release.",
            "Temporarily raise pool max connections or shed non-critical background workers.",
        ],
    },
    {
        "id": "disk-full",
        "title": "Disk Full / No Space Left on Device",
        "pattern": r"(no space left on device|enospc|disk full|volume full)",
        "steps": [
            "Check filesystem and inode usage (`df -h` and `df -i`).",
            "Clear rotated logs or orphaned temporary artifacts and verify log rotation.",
            "Expand persistent volume claim if data growth is legitimate.",
        ],
    },
    {
        "id": "tls-expired",
        "title": "TLS Certificate Expired or Handshake Failure",
        "pattern": r"(certificate has expired|x509|tls handshake|ssl_error|cert_authority_invalid)",
        "steps": [
            "Inspect certificate expiry with `openssl s_client -connect <host>:443`.",
            "Check cert-manager / ACME renewal logs and force certificate rotation.",
            "Reload ingress controller or load balancer after renewing the secret.",
        ],
    },
    {
        "id": "upstream-rate-limit",
        "title": "Upstream Rate Limit (HTTP 429)",
        "pattern": r"(429 too many requests|rate limit exceeded|throttlingexception)",
        "steps": [
            "Identify the upstream provider returning 429 and check `Retry-After` headers.",
            "Enable exponential backoff with jitter and inspect recent retry storms.",
            "Verify API quota usage and request a temporary limit increase if needed.",
        ],
    },
]


def load_runbooks(config_path: str) -> list[dict[str, object]]:
    """Load custom runbooks from YAML and merge with built-in defaults."""
    items = list(DEFAULT_RUNBOOKS)
    path = Path(config_path)
    if not path.exists():
        return items
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    custom = raw.get("runbooks") if isinstance(raw, dict) else []
    if isinstance(custom, list):
        for entry in custom:
            if isinstance(entry, dict) and entry.get("pattern") and entry.get("title"):
                items.insert(0, entry)
    return items


def match_runbooks(
    event: IncidentEvent,
    logs: list[LogEntry],
    config_path: str = "./runbooks.yaml",
) -> list[RunbookMatch]:
    """Match alert text and recent error logs against operational runbooks."""
    corpus = "\n".join(
        [
            event.title,
            event.description,
            event.stacktrace_hint,
            *(log.message for log in logs[:15]),
        ]
    )
    matches: list[RunbookMatch] = []
    seen_ids: set[str] = set()

    for rb in load_runbooks(config_path):
        rb_id = str(rb.get("id") or rb.get("title"))
        if rb_id in seen_ids:
            continue
        pattern = str(rb.get("pattern") or "")
        if not pattern:
            continue
        m = re.search(pattern, corpus, flags=re.IGNORECASE)
        if m:
            seen_ids.add(rb_id)
            steps = [str(s) for s in (rb.get("steps") or [])]
            matches.append(
                RunbookMatch(
                    id=rb_id,
                    title=str(rb.get("title")),
                    matched_pattern=m.group(0),
                    steps=steps,
                )
            )
    return matches
