"""Correlation scoring engine matching stack traces, logs, and Git commits."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath

from incidentpilot.collectors.stacktrace import normalize_file_path
from incidentpilot.models import (
    CommitInfo,
    CorrelationCandidate,
    DeploymentInfo,
    IncidentEvent,
    LogEntry,
    ParsedStackTrace,
)


def _paths_match(frame_path: str, commit_file_path: str) -> tuple[bool, bool]:
    """Return (matched, exact_suffix_match) between a stack frame path and repo path."""
    f_norm = normalize_file_path(frame_path)
    c_norm = normalize_file_path(commit_file_path)
    if not f_norm or not c_norm:
        return False, False
    if f_norm == c_norm or f_norm.endswith("/" + c_norm) or c_norm.endswith("/" + f_norm):
        return True, True
    if PurePosixPath(f_norm).name == PurePosixPath(c_norm).name:
        return True, False
    return False, False


def select_rollback_target(
    deployments: list[DeploymentInfo], suspect_commit: CommitInfo | None
) -> str:
    """Choose the safest previous stable release tag or parent commit for rollback."""
    if len(deployments) >= 2:
        for dep in deployments:
            if suspect_commit and dep.commit_sha and suspect_commit.sha.startswith(dep.commit_sha):
                continue
            return dep.version or dep.tag
        return deployments[1].version or deployments[1].tag
    if len(deployments) == 1:
        dep = deployments[0]
        if suspect_commit and dep.commit_sha and not suspect_commit.sha.startswith(dep.commit_sha):
            return dep.version or dep.tag
        if suspect_commit:
            return f"{suspect_commit.short_sha}~1"
        return dep.version or dep.tag
    if suspect_commit:
        return f"{suspect_commit.short_sha}~1"
    return "previous-stable"


def correlate_incident(
    event: IncidentEvent,
    logs: list[LogEntry],
    stacktraces: list[ParsedStackTrace],
    commits: list[CommitInfo],
    deployments: list[DeploymentInfo],
) -> list[CorrelationCandidate]:
    """Rank recent commits by correlation strength with the incident evidence."""
    if not commits:
        return []

    error_text = " ".join(
        [
            event.title,
            event.description,
            event.service,
            *(st.error_type + " " + st.error_message for st in stacktraces[:3]),
            *(log.message for log in logs[:5]),
        ]
    ).lower()

    all_frames = [frame for st in stacktraces for frame in st.frames]
    candidates: list[CorrelationCandidate] = []

    for commit in commits:
        score = 0.0
        reasons: list[str] = []
        matched_files: list[str] = []
        matched_lines: list[str] = []

        best_file_pts = 0.0
        best_line_pts = 0.0

        for fdiff in commit.files:
            for frame in all_frames:
                matched, exact_suffix = _paths_match(frame.file, fdiff.path)
                if not matched:
                    continue
                if fdiff.path not in matched_files:
                    matched_files.append(fdiff.path)
                file_pts = 45.0 if exact_suffix else 32.0
                if file_pts > best_file_pts:
                    best_file_pts = file_pts

                if frame.line is not None and fdiff.changed_line_ranges:
                    for start, end in fdiff.changed_line_ranges:
                        if start <= frame.line <= end:
                            best_line_pts = max(best_line_pts, 25.0)
                            loc = f"{fdiff.path}:{frame.line}"
                            if loc not in matched_lines:
                                matched_lines.append(loc)
                        elif abs(frame.line - start) <= 15 or abs(frame.line - end) <= 15:
                            best_line_pts = max(best_line_pts, 15.0)
                            loc = f"{fdiff.path}:{frame.line} (near hunk {start}-{end})"
                            if loc not in matched_lines:
                                matched_lines.append(loc)

        if best_file_pts > 0:
            score += best_file_pts
            reasons.append(f"Modified stack-trace file(s): {', '.join(matched_files)}")
        if best_line_pts > 0:
            score += best_line_pts
            reasons.append(f"Diff hunk overlaps crash location: {', '.join(matched_lines)}")

        # Recency score relative to incident trigger time
        age_hours = max(
            0.0,
            (event.triggered_at - commit.timestamp).total_seconds() / 3600.0,
        )
        if age_hours <= 1.0:
            score += 15.0
            reasons.append("Committed within 1 hour before incident")
        elif age_hours <= 6.0:
            score += 10.0
            reasons.append("Committed within 6 hours before incident")
        elif age_hours <= 24.0:
            score += 5.0
            reasons.append("Committed within 24 hours before incident")

        # Keyword / service overlap
        msg_lower = commit.message.lower()
        patch_lower = " ".join(f.patch.lower() for f in commit.files[:5])
        keyword_hits = 0
        for token in {event.service.lower(), "panic", "nil", "null", "pointer", "timeout", "checkout", "payment"}:
            if len(token) >= 3 and token in error_text and (token in msg_lower or token in patch_lower):
                keyword_hits += 1
        if keyword_hits > 0:
            kw_pts = min(15.0, keyword_hits * 5.0)
            score += kw_pts
            reasons.append("Commit message or diff shares error/service keywords")

        # Service path boost when no stacktrace frames matched directly
        if not matched_files and event.service != "unknown-service":
            svc = event.service.lower().replace("-service", "")
            svc_files = [f.path for f in commit.files if svc in f.path.lower()]
            if svc_files:
                score += 20.0
                matched_files.extend(svc_files)
                reasons.append(f"Touched service directory files: {', '.join(svc_files[:3])}")

        bounded_score = round(min(score, 100.0), 1)
        if bounded_score > 0:
            candidates.append(
                CorrelationCandidate(
                    commit=commit,
                    score=bounded_score,
                    reasons=reasons,
                    matched_files=matched_files,
                    matched_lines=matched_lines,
                    rollback_target=select_rollback_target(deployments, commit),
                )
            )

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates
