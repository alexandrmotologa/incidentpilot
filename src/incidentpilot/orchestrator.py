"""Autonomous 60-second incident investigation and remediation orchestrator."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import timedelta

from incidentpilot.collectors.git import GitProvider, build_git_provider, default_git_since
from incidentpilot.collectors.logs import LogCollector, build_log_collector
from incidentpilot.collectors.stacktrace import parse_stacktrace
from incidentpilot.config import Settings
from incidentpilot.correlator.engine import correlate_incident
from incidentpilot.correlator.synthesizer import synthesize_brief
from incidentpilot.integrations.rollback import RollbackExecutor
from incidentpilot.integrations.slack import SlackClient
from incidentpilot.models import (
    IncidentEvent,
    IncidentRecord,
    IncidentStatus,
    ParsedStackTrace,
    RollbackRecord,
    TimelineStep,
)
from incidentpilot.storage import IncidentStore


class IncidentOrchestrator:
    """Coordinates alert ingestion, parallel evidence collection, correlation, Slack brief, and rollback."""

    def __init__(
        self,
        settings: Settings,
        store: IncidentStore,
        log_collector: LogCollector | None = None,
        git_provider: GitProvider | None = None,
        slack_client: SlackClient | None = None,
        rollback_executor: RollbackExecutor | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.log_collector = log_collector or build_log_collector(settings)
        self.git_provider = git_provider or build_git_provider(settings)
        self.slack_client = slack_client or SlackClient(settings)
        self.rollback_executor = rollback_executor or RollbackExecutor(settings)
        self._sse_subscribers: list[asyncio.Queue[dict[str, str]]] = []

    def subscribe_events(self) -> asyncio.Queue[dict[str, str]]:
        """Register a listener queue for real-time SSE dashboard updates."""
        queue: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=100)
        self._sse_subscribers.append(queue)
        return queue

    def unsubscribe_events(self, queue: asyncio.Queue[dict[str, str]]) -> None:
        """Remove an SSE listener queue."""
        if queue in self._sse_subscribers:
            self._sse_subscribers.remove(queue)

    async def _broadcast(self, event_type: str, incident_id: str) -> None:
        msg = {"event": event_type, "incident_id": incident_id}
        for q in list(self._sse_subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    async def ingest_event(
        self, event: IncidentEvent, wait_for_investigation: bool = False
    ) -> tuple[IncidentRecord, bool]:
        """Ingest a normalized alert, deduplicate, and launch autonomous investigation.

        Returns (record, deduplicated).
        """
        existing = await self.store.find_active_by_fingerprint(
            event.fingerprint, self.settings.dedup_window_seconds
        )
        if existing:
            existing.alert_count += 1
            existing.timeline.append(
                TimelineStep(
                    stage="alert_deduplicated",
                    detail=f"Suppressed duplicate alert from {event.source.value} (count={existing.alert_count})",
                )
            )
            await self.store.save_incident(existing)
            await self._broadcast("incident_updated", existing.id)
            return existing, True

        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        record = IncidentRecord(
            id=incident_id,
            event=event,
            status=IncidentStatus.INVESTIGATING,
            timeline=[
                TimelineStep(
                    stage="webhook_received",
                    detail=f"Received {event.severity.value} alert from {event.source.value} for {event.service}",
                )
            ],
        )
        await self.store.save_incident(record)
        await self._broadcast("incident_created", record.id)

        if wait_for_investigation:
            record = await self.investigate(record.id)
        else:
            asyncio.create_task(self.investigate(record.id))

        return record, False

    async def investigate(self, incident_id: str) -> IncidentRecord:
        """Run the full log/git/stacktrace correlation pipeline within the 60s SLA."""
        record = await self.store.get_incident(incident_id)
        if record is None:
            raise KeyError(f"Incident {incident_id} not found")

        started = time.perf_counter()
        event = record.event
        since_logs = event.triggered_at - timedelta(minutes=self.settings.log_window_minutes)
        until_logs = event.triggered_at + timedelta(minutes=2)
        since_git = default_git_since(self.settings)

        async def _collect() -> tuple[list, list, list]:
            return await asyncio.gather(
                self.log_collector.fetch_error_logs(event.service, since_logs, until_logs),
                self.git_provider.fetch_recent_commits(since_git, limit=25),
                self.git_provider.fetch_recent_deployments(event.environment, limit=10),
            )

        t_collect = time.perf_counter()
        logs, commits, deployments = await asyncio.wait_for(
            _collect(), timeout=float(self.settings.investigation_timeout_seconds)
        )
        collect_ms = int((time.perf_counter() - t_collect) * 1000)
        record.timeline.append(
            TimelineStep(
                stage="evidence_collected",
                detail=f"Fetched {len(logs)} error logs (15m window), {len(commits)} commits, {len(deployments)} deployments",
                duration_ms=collect_ms,
            )
        )

        # Parse stack traces from webhook hint and error logs
        t_parse = time.perf_counter()
        stacktraces: list[ParsedStackTrace] = []
        if event.stacktrace_hint:
            parsed = parse_stacktrace(event.stacktrace_hint)
            if parsed:
                stacktraces.append(parsed)
        for log in logs:
            raw_trace = log.stacktrace or log.message
            parsed = parse_stacktrace(raw_trace)
            if parsed and parsed.frames:
                stacktraces.append(parsed)
        parse_ms = int((time.perf_counter() - t_parse) * 1000)
        record.timeline.append(
            TimelineStep(
                stage="stacktrace_parsed",
                detail=f"Extracted {len(stacktraces)} structured stack trace(s)",
                duration_ms=parse_ms,
            )
        )

        # Correlate evidence
        t_corr = time.perf_counter()
        candidates = correlate_incident(event, logs, stacktraces, commits, deployments)
        corr_ms = int((time.perf_counter() - t_corr) * 1000)
        top_msg = (
            f"Top suspect: {candidates[0].commit.short_sha} (score {candidates[0].score:.1f}%)"
            if candidates
            else "No direct commit match found"
        )
        record.timeline.append(
            TimelineStep(
                stage="correlation_completed",
                detail=top_msg,
                duration_ms=corr_ms,
            )
        )

        total_ms = int((time.perf_counter() - started) * 1000)
        brief = await synthesize_brief(
            settings=self.settings,
            incident_id=record.id,
            event=event,
            logs=logs,
            stacktraces=stacktraces,
            candidates=candidates,
            deployments=deployments,
            duration_ms=total_ms,
        )
        record.brief = brief

        # Dispatch Slack brief
        slack_res = await self.slack_client.send_brief(record)
        if slack_res.get("ts"):
            record.slack_message_ts = str(slack_res["ts"])
        record.status = IncidentStatus.BRIEF_SENT
        record.timeline.append(
            TimelineStep(
                stage="brief_dispatched",
                detail=(
                    "Sent Incident Brief to Slack"
                    if slack_res.get("delivered")
                    else "Brief ready in dashboard (Slack webhook/token not configured)"
                ),
                duration_ms=int((time.perf_counter() - started) * 1000) - total_ms,
            )
        )

        await self.store.save_incident(record)
        await self._broadcast("incident_updated", record.id)
        return record

    async def trigger_rollback(
        self,
        incident_id: str,
        target_version: str | None = None,
        requested_by: str = "oncall-engineer",
    ) -> tuple[IncidentRecord, RollbackRecord]:
        """Execute a confirmed rollback and persist audit logs."""
        record = await self.store.get_incident(incident_id)
        if record is None:
            raise KeyError(f"Incident {incident_id} not found")

        resolved_target = target_version or (
            record.brief.rollback_target if record.brief and record.brief.rollback_target else "previous-stable"
        )
        record.status = IncidentStatus.ROLLBACK_PENDING
        await self.store.save_incident(record)
        await self._broadcast("incident_updated", record.id)

        rb = await self.rollback_executor.execute(
            record=record,
            target_version=resolved_target,
            requested_by=requested_by,
        )
        await self.store.save_rollback(rb)
        record.rollbacks.append(rb)
        record.status = (
            IncidentStatus.ROLLED_BACK if rb.status == "succeeded" else IncidentStatus.ROLLBACK_FAILED
        )
        record.timeline.append(
            TimelineStep(
                stage="rollback_executed",
                detail=(
                    f"Rolled back to {resolved_target}: {rb.output}"
                    if rb.status == "succeeded"
                    else f"Rollback to {resolved_target} failed: {rb.error}"
                ),
            )
        )
        await self.store.save_incident(record)
        await self._broadcast("incident_updated", record.id)
        return record, rb

    async def dismiss_incident(
        self, incident_id: str, actor: str = "oncall-engineer"
    ) -> IncidentRecord:
        """Mark an incident as dismissed."""
        record = await self.store.get_incident(incident_id)
        if record is None:
            raise KeyError(f"Incident {incident_id} not found")
        record.status = IncidentStatus.DISMISSED
        record.timeline.append(
            TimelineStep(stage="incident_dismissed", detail=f"Dismissed by {actor}")
        )
        await self.store.save_incident(record)
        await self._broadcast("incident_updated", record.id)
        return record


def generate_postmortem_markdown(record: IncidentRecord) -> str:
    """Render a structured Markdown postmortem from an IncidentRecord."""
    ev = record.event
    brief = record.brief
    lines = [
        f"# Postmortem: {ev.title} ({record.id})",
        "",
        f"- Service: `{ev.service}` ({ev.environment})",
        f"- Severity: `{ev.severity.value}`",
        f"- Source: `{ev.source.value}`",
        f"- Status: `{record.status.value}`",
        f"- Triggered at: `{ev.triggered_at.isoformat()}`",
        f"- Deduplicated alert count: `{record.alert_count}`",
        "",
        "## Root cause summary",
        "",
        brief.probable_cause if brief else "Investigation did not complete.",
        "",
        "## Recommendation",
        "",
        brief.recommendation if brief else "Manual investigation required.",
        "",
    ]
    if brief and brief.evidence:
        lines.append("## Evidence")
        lines.append("")
        for item in brief.evidence:
            lines.append(f"- {item}")
        lines.append("")

    if brief and brief.top_candidate:
        c = brief.top_candidate.commit
        lines.extend(
            [
                "## Suspect commit",
                "",
                f"- SHA: `{c.sha}`",
                f"- Author: {c.author}",
                f"- Message: {c.message}",
                f"- Timestamp: `{c.timestamp.isoformat()}`",
                "",
            ]
        )

    lines.append("## Investigation timeline")
    lines.append("")
    for step in record.timeline:
        lines.append(f"- `{step.timestamp.isoformat()}` [{step.stage}] {step.detail} ({step.duration_ms} ms)")

    if record.rollbacks:
        lines.extend(["", "## Rollback history", ""])
        for rb in record.rollbacks:
            detail = rb.output if rb.status == "succeeded" else rb.error
            lines.append(
                f"- `{rb.executed_at.isoformat()}` target=`{rb.target_version}` status=`{rb.status}` by `{rb.requested_by}`: {detail}"
            )

    lines.append("")
    return "\n".join(lines)
