"""Domain models for IncidentPilot."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


class AlertSource(str, Enum):
    PAGERDUTY = "pagerduty"
    ALERTMANAGER = "alertmanager"
    SENTRY = "sentry"
    GENERIC = "generic"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    INVESTIGATING = "investigating"
    BRIEF_SENT = "brief_sent"
    ROLLBACK_PENDING = "rollback_pending"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"


class IncidentEvent(BaseModel):
    """Normalized alert payload from any monitoring source."""

    source: AlertSource
    external_id: str
    fingerprint: str
    service: str
    environment: str = "production"
    title: str
    description: str = ""
    severity: Severity = Severity.HIGH
    triggered_at: datetime = Field(default_factory=utc_now)
    stacktrace_hint: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class StackFrame(BaseModel):
    """Single parsed frame from a stack trace."""

    file: str
    line: int | None = None
    function: str = ""
    language: str = "unknown"
    raw: str = ""


class ParsedStackTrace(BaseModel):
    """Structured representation of a crash or exception stack trace."""

    error_type: str = ""
    error_message: str = ""
    language: str = "unknown"
    frames: list[StackFrame] = Field(default_factory=list)


class LogEntry(BaseModel):
    """Single log record retrieved from a log backend."""

    timestamp: datetime
    level: str = "ERROR"
    service: str
    message: str
    trace_id: str = ""
    stacktrace: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class FileDiff(BaseModel):
    """Changed file and line-range metadata in a Git commit."""

    path: str
    additions: int = 0
    deletions: int = 0
    patch: str = ""
    changed_line_ranges: list[tuple[int, int]] = Field(default_factory=list)


class CommitInfo(BaseModel):
    """Git commit metadata and diff."""

    sha: str
    short_sha: str
    author: str
    email: str = ""
    message: str
    timestamp: datetime
    files: list[FileDiff] = Field(default_factory=list)
    url: str = ""


class DeploymentInfo(BaseModel):
    """Deployment or release tag record."""

    id: str
    version: str
    tag: str = ""
    commit_sha: str = ""
    environment: str = "production"
    created_at: datetime
    status: str = "success"


class CorrelationCandidate(BaseModel):
    """Ranked commit candidate with explainable correlation evidence."""

    commit: CommitInfo
    score: float = Field(ge=0.0, le=100.0)
    reasons: list[str] = Field(default_factory=list)
    matched_files: list[str] = Field(default_factory=list)
    matched_lines: list[str] = Field(default_factory=list)
    rollback_target: str = ""


class IncidentBrief(BaseModel):
    """Synthesized root-cause analysis and action recommendation."""

    incident_id: str
    summary: str
    probable_cause: str
    recommendation: str
    rollback_target: str = ""
    confidence: float = Field(ge=0.0, le=100.0)
    evidence: list[str] = Field(default_factory=list)
    error_count_15m: int = 0
    top_stacktrace: ParsedStackTrace | None = None
    top_candidate: CorrelationCandidate | None = None
    investigation_duration_ms: int = 0
    synthesis_mode: str = "deterministic"


class TimelineStep(BaseModel):
    """Single timestamped step in the autonomous investigation."""

    timestamp: datetime = Field(default_factory=utc_now)
    stage: str
    detail: str
    duration_ms: int = 0


class RollbackRecord(BaseModel):
    """Audit record for a triggered rollback action."""

    id: str
    incident_id: str
    target_version: str
    provider: str
    status: str
    requested_by: str = "oncall-engineer"
    executed_at: datetime = Field(default_factory=utc_now)
    output: str = ""
    error: str = ""


class IncidentRecord(BaseModel):
    """Full persisted incident state."""

    id: str
    event: IncidentEvent
    status: IncidentStatus = IncidentStatus.INVESTIGATING
    alert_count: int = 1
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    brief: IncidentBrief | None = None
    timeline: list[TimelineStep] = Field(default_factory=list)
    rollbacks: list[RollbackRecord] = Field(default_factory=list)
    slack_message_ts: str = ""
