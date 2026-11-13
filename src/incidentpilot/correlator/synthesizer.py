"""Root-cause brief synthesis (LLM-assisted with deterministic fallback)."""

from __future__ import annotations

import json
from pathlib import PurePosixPath

import httpx

from incidentpilot.config import Settings
from incidentpilot.models import (
    CorrelationCandidate,
    DeploymentInfo,
    IncidentBrief,
    IncidentEvent,
    LogEntry,
    ParsedStackTrace,
)


def _deterministic_brief(
    incident_id: str,
    event: IncidentEvent,
    logs: list[LogEntry],
    stacktraces: list[ParsedStackTrace],
    candidates: list[CorrelationCandidate],
    deployments: list[DeploymentInfo],
    duration_ms: int,
) -> IncidentBrief:
    top_st = stacktraces[0] if stacktraces else None
    top_cand = candidates[0] if candidates else None

    evidence: list[str] = [
        f"Collected {len(logs)} error log(s) for service '{event.service}' in the last 15 minutes."
    ]
    if top_st and top_st.frames:
        lead_frame = top_st.frames[0]
        loc = f"{lead_frame.file}:{lead_frame.line}" if lead_frame.line else lead_frame.file
        err_desc = f"{top_st.error_type}: {top_st.error_message}".strip(": ")
        evidence.append(f"Primary stack frame: {loc} ({err_desc or 'runtime exception'}).")

    if top_cand:
        evidence.extend(top_cand.reasons)
        commit = top_cand.commit
        rollback_target = top_cand.rollback_target or "previous-stable"

        location_str = ""
        if top_cand.matched_lines:
            location_str = top_cand.matched_lines[0].split(" ")[0]
        elif top_cand.matched_files:
            location_str = PurePosixPath(top_cand.matched_files[0]).name
        elif top_st and top_st.frames:
            f0 = top_st.frames[0]
            location_str = f"{PurePosixPath(f0.file).name}:{f0.line}" if f0.line else PurePosixPath(f0.file).name

        err_summary = (
            top_st.error_message
            if top_st and top_st.error_message
            else event.title
        )
        loc_clause = f" in {location_str}" if location_str else ""
        probable_cause = (
            f"Commit {commit.short_sha} by {commit.author} ('{commit.message}') "
            f"correlates with {err_summary}{loc_clause}."
        )
        recommendation = f"Rollback {event.service} to {rollback_target}"
        confidence = top_cand.score
    else:
        rollback_target = deployments[1].version if len(deployments) >= 2 else "previous-stable"
        probable_cause = (
            f"No recent commit directly matched the stack trace; "
            f"observed {len(logs)} error(s) for {event.service}: {event.title}."
        )
        recommendation = (
            f"Inspect recent logs and consider rolling back {event.service} to {rollback_target}"
        )
        confidence = 25.0 if logs else 10.0

    summary = f"{probable_cause} Recommendation: {recommendation}."
    return IncidentBrief(
        incident_id=incident_id,
        summary=summary,
        probable_cause=probable_cause,
        recommendation=recommendation,
        rollback_target=rollback_target,
        confidence=confidence,
        evidence=evidence,
        error_count_15m=len(logs),
        top_stacktrace=top_st,
        top_candidate=top_cand,
        investigation_duration_ms=duration_ms,
        synthesis_mode="deterministic",
    )


async def synthesize_brief(
    settings: Settings,
    incident_id: str,
    event: IncidentEvent,
    logs: list[LogEntry],
    stacktraces: list[ParsedStackTrace],
    candidates: list[CorrelationCandidate],
    deployments: list[DeploymentInfo],
    duration_ms: int,
) -> IncidentBrief:
    """Generate an IncidentBrief using an LLM if configured, else deterministic evidence synthesis."""
    base_brief = _deterministic_brief(
        incident_id=incident_id,
        event=event,
        logs=logs,
        stacktraces=stacktraces,
        candidates=candidates,
        deployments=deployments,
        duration_ms=duration_ms,
    )

    if not settings.llm_api_key:
        return base_brief

    context_payload = {
        "service": event.service,
        "title": event.title,
        "severity": event.severity.value,
        "error_count_15m": len(logs),
        "stacktrace": stacktraces[0].model_dump() if stacktraces else None,
        "top_candidate": {
            "sha": candidates[0].commit.short_sha,
            "author": candidates[0].commit.author,
            "message": candidates[0].commit.message,
            "score": candidates[0].score,
            "matched_lines": candidates[0].matched_lines,
            "rollback_target": candidates[0].rollback_target,
        }
        if candidates
        else None,
    }

    prompt = (
        "You are an autonomous SRE incident responder. Given the JSON evidence below, "
        "return ONLY a JSON object with keys 'probable_cause', 'recommendation', and 'summary'. "
        "Keep each field concise, factual, and grounded strictly in the provided commit SHA, file, line, and version.\n"
        f"Evidence:\n{json.dumps(context_payload)}"
    )

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                settings.llm_api_url,
                headers={
                    "Authorization": f"Bearer {settings.llm_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.llm_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            base_brief.probable_cause = str(parsed.get("probable_cause") or base_brief.probable_cause)
            base_brief.recommendation = str(parsed.get("recommendation") or base_brief.recommendation)
            base_brief.summary = str(parsed.get("summary") or base_brief.summary)
            base_brief.synthesis_mode = "llm"
    except Exception:
        # Never fail an incident brief if external LLM API errors or times out
        pass

    return base_brief
