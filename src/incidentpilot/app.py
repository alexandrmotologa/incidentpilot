"""FastAPI application for IncidentPilot."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from incidentpilot.config import Settings, get_settings
from incidentpilot.orchestrator import IncidentOrchestrator, generate_postmortem_markdown
from incidentpilot.simulator import ScenarioName, run_scenario_simulation
from incidentpilot.storage import IncidentStore
from incidentpilot.webhooks import (
    parse_alertmanager_webhook,
    parse_generic_webhook,
    parse_pagerduty_webhook,
    parse_sentry_webhook,
    verify_bearer_token,
    verify_pagerduty_signature,
    verify_sentry_signature,
    verify_slack_signature,
)

STATIC_DIR = Path(__file__).parent / "static"


class RollbackRequest(BaseModel):
    target_version: str | None = None
    requested_by: str = "oncall-engineer"


class DismissRequest(BaseModel):
    actor: str = "oncall-engineer"


class SimulateRequest(BaseModel):
    scenario: ScenarioName = "go_nil_pointer"


def create_app(
    settings: Settings | None = None,
    orchestrator: IncidentOrchestrator | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    cfg = settings or get_settings()
    store = IncidentStore(cfg.db_path)
    orch = orchestrator or IncidentOrchestrator(settings=cfg, store=store)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await store.initialize()
        yield

    app = FastAPI(
        title="IncidentPilot",
        description="Autonomous on-call incident responder and log/trace/Git correlator.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.state.store = store
    app.state.orchestrator = orch

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> Response:
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            return HTMLResponse("<h1>IncidentPilot API</h1><p>Dashboard assets not found.</p>")
        return HTMLResponse(index_file.read_text(encoding="utf-8"))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {
            "status": "ok",
            "log_provider": cfg.log_provider,
            "git_provider": cfg.git_provider,
            "rollback_provider": cfg.rollback_provider,
        }

    async def _ingest_list(events: list[Any], sync: bool) -> dict[str, Any]:
        results = []
        for ev in events:
            record, deduped = await orch.ingest_event(ev, wait_for_investigation=sync)
            if record is None:
                results.append({"incident_id": None, "status": "no_active_incident", "deduplicated": False})
                continue
            results.append(
                {
                    "incident_id": record.id,
                    "status": record.status.value,
                    "deduplicated": deduped,
                    "alert_count": record.alert_count,
                }
            )
        return {"accepted": len(results), "incidents": results}

    @app.post("/webhooks/pagerduty")
    async def webhook_pagerduty(
        request: Request, sync: bool = Query(default=False)
    ) -> dict[str, Any]:
        raw = await request.body()
        sig = request.headers.get("X-PagerDuty-Signature")
        if not verify_pagerduty_signature(raw, sig, cfg.pagerduty_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid PagerDuty signature")
        payload = json.loads(raw.decode("utf-8"))
        events = parse_pagerduty_webhook(payload)
        return await _ingest_list(events, sync)

    @app.post("/webhooks/alertmanager")
    async def webhook_alertmanager(
        request: Request, sync: bool = Query(default=False)
    ) -> dict[str, Any]:
        auth = request.headers.get("Authorization")
        if not verify_bearer_token(auth, cfg.alertmanager_bearer_token):
            raise HTTPException(status_code=401, detail="Invalid Alertmanager bearer token")
        payload = await request.json()
        events = parse_alertmanager_webhook(payload)
        return await _ingest_list(events, sync)

    @app.post("/webhooks/sentry")
    async def webhook_sentry(
        request: Request, sync: bool = Query(default=False)
    ) -> dict[str, Any]:
        raw = await request.body()
        sig = request.headers.get("Sentry-Hook-Signature")
        if not verify_sentry_signature(raw, sig, cfg.sentry_client_secret):
            raise HTTPException(status_code=401, detail="Invalid Sentry signature")
        payload = json.loads(raw.decode("utf-8"))
        events = parse_sentry_webhook(payload)
        return await _ingest_list(events, sync)

    @app.post("/webhooks/generic")
    async def webhook_generic(
        request: Request, sync: bool = Query(default=False)
    ) -> dict[str, Any]:
        payload = await request.json()
        events = parse_generic_webhook(payload)
        return await _ingest_list(events, sync)

    @app.post("/integrations/slack/actions")
    async def slack_actions(request: Request) -> dict[str, Any]:
        raw = await request.body()
        ts = request.headers.get("X-Slack-Request-Timestamp")
        sig = request.headers.get("X-Slack-Signature")
        if not verify_slack_signature(raw, ts, sig, cfg.slack_signing_secret):
            raise HTTPException(status_code=401, detail="Invalid Slack signature")

        form = await request.form()
        payload_raw = form.get("payload")
        if not payload_raw:
            raise HTTPException(status_code=400, detail="Missing Slack payload")
        payload = json.loads(str(payload_raw))

        user_obj = payload.get("user") or {}
        actor = str(user_obj.get("username") or user_obj.get("name") or "slack-user")
        response_url = str(payload.get("response_url") or "")
        actions = payload.get("actions") or []

        for action in actions:
            action_id = action.get("action_id")
            value = str(action.get("value") or "")
            if action_id == "confirm_rollback":
                if "|" in value:
                    incident_id, target_version = value.split("|", 1)
                else:
                    incident_id, target_version = value, None
                try:
                    record, rb = await orch.trigger_rollback(
                        incident_id=incident_id,
                        target_version=target_version,
                        requested_by=actor,
                    )
                except KeyError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc
                await orch.slack_client.post_response_url(response_url, record)
                return {"ok": True, "incident_id": record.id, "rollback_status": rb.status}

            if action_id == "dismiss_incident":
                try:
                    record = await orch.dismiss_incident(incident_id=value, actor=actor)
                except KeyError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc
                await orch.slack_client.post_response_url(response_url, record)
                return {"ok": True, "incident_id": record.id, "status": record.status.value}

        return {"ok": True, "ignored": True}

    @app.get("/api/incidents")
    async def list_incidents(
        limit: int = Query(default=50, ge=1, le=200),
        service: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        status: str | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        records = await store.list_incidents(
            limit=limit, service=service, severity=severity, status=status
        )
        return [r.model_dump(mode="json") for r in records]

    @app.get("/api/metrics")
    async def get_metrics() -> dict[str, Any]:
        metrics = await store.compute_metrics()
        return metrics.model_dump(mode="json")

    @app.post("/api/simulate")
    async def api_simulate(body: SimulateRequest) -> dict[str, Any]:
        record = await run_scenario_simulation(
            store=store,
            base_settings=cfg,
            scenario=body.scenario,
            broadcast_orch=orch,
        )
        return record.model_dump(mode="json")

    @app.get("/api/incidents/{incident_id}")
    async def get_incident(incident_id: str) -> dict[str, Any]:
        record = await store.get_incident(incident_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return record.model_dump(mode="json")

    @app.post("/api/incidents/{incident_id}/rollback")
    async def api_rollback(incident_id: str, body: RollbackRequest) -> dict[str, Any]:
        try:
            record, rb = await orch.trigger_rollback(
                incident_id=incident_id,
                target_version=body.target_version,
                requested_by=body.requested_by,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {
            "incident": record.model_dump(mode="json"),
            "rollback": rb.model_dump(mode="json"),
        }

    @app.post("/api/incidents/{incident_id}/dismiss")
    async def api_dismiss(incident_id: str, body: DismissRequest) -> dict[str, Any]:
        try:
            record = await orch.dismiss_incident(incident_id=incident_id, actor=body.actor)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return record.model_dump(mode="json")

    @app.get("/api/incidents/{incident_id}/postmortem.md", response_class=PlainTextResponse)
    async def export_postmortem(incident_id: str) -> str:
        record = await store.get_incident(incident_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return generate_postmortem_markdown(record)

    @app.get("/api/events")
    async def sse_events(request: Request) -> StreamingResponse:
        queue = orch.subscribe_events()

        async def event_stream():
            try:
                yield "event: connected\ndata: {}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield f"event: {msg['event']}\ndata: {json.dumps(msg)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                orch.unsubscribe_events(queue)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app
