"""Tests for the correlation engine."""

from datetime import datetime, timedelta, timezone

from incidentpilot.correlator.engine import correlate_incident
from incidentpilot.models import (
    AlertSource,
    CommitInfo,
    DeploymentInfo,
    FileDiff,
    IncidentEvent,
    ParsedStackTrace,
    StackFrame,
)


def test_correlate_ranks_matching_file_and_line_highest() -> None:
    now = datetime.now(timezone.utc)
    event = IncidentEvent(
        source=AlertSource.PAGERDUTY,
        external_id="1",
        fingerprint="fp1",
        service="checkout",
        title="Panic in checkout",
        triggered_at=now,
    )
    st = ParsedStackTrace(
        error_type="panic",
        error_message="nil pointer dereference",
        language="go",
        frames=[StackFrame(file="/app/pkg/checkout/checkout.go", line=114, language="go")],
    )
    bad_commit = CommitInfo(
        sha="8f2a1c999999",
        short_sha="8f2a1c",
        author="dev",
        message="refactor checkout pointer",
        timestamp=now - timedelta(minutes=20),
        files=[
            FileDiff(
                path="pkg/checkout/checkout.go",
                additions=3,
                deletions=1,
                patch="@@ -110,5 +110,6 @@",
                changed_line_ranges=[(110, 115)],
            )
        ],
    )
    unrelated_commit = CommitInfo(
        sha="111111111111",
        short_sha="111111",
        author="dev2",
        message="update docs",
        timestamp=now - timedelta(minutes=10),
        files=[FileDiff(path="README.md", additions=2, deletions=0)],
    )
    deployments = [
        DeploymentInfo(id="2", version="v2.4.2", tag="v2.4.2", commit_sha="8f2a1c9", created_at=now),
        DeploymentInfo(id="1", version="v2.4.1", tag="v2.4.1", commit_sha="0000000", created_at=now - timedelta(hours=5)),
    ]

    ranked = correlate_incident(event, [], [st], [unrelated_commit, bad_commit], deployments)
    assert len(ranked) >= 1
    assert ranked[0].commit.short_sha == "8f2a1c"
    assert ranked[0].score >= 80.0
    assert ranked[0].rollback_target == "v2.4.1"
