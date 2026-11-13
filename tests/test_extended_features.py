"""Tests for auto-resolve, MTTR, SRE metrics, spike ratio, filters, and simulator."""

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from incidentpilot.app import create_app
from incidentpilot.config import Settings
from incidentpilot.correlator.synthesizer import _compute_spike_ratio
from incidentpilot.models import (
    AlertSource,
    IncidentEvent,
    IncidentRecord,
    IncidentStatus,
    Severity,
    TimelineStep,
)
from incidentpilot.storage import IncidentStore


def test_compute_spike_ratio() -> None:
    # 0 baseline -> returns current count
    assert _compute_spike_ratio(10, 0) == 10.0
    # Normal baseline: 30 errors in 45m = 10 errors / 15m. 25 current errors = 2.5x spike
    assert _compute_spike_ratio(25, 30) == 2.5
    # No errors at all
    assert _compute_spike_ratio(0, 0) is None


async def test_auto_resolve_and_mttr(tmp_path: Path) -> None:
    db = str(tmp_path / "test.db")
    store = IncidentStore(db)
    await store.initialize()

    now = datetime.now(timezone.utc)
    ev_firing = IncidentEvent(
        source=AlertSource.ALERTMANAGER,
        external_id="am-10",
        fingerprint="fp-resolve-test",
        service="order-api",
        title="Order latency spike",
        severity=Severity.HIGH,
        triggered_at=now,
    )
    rec = IncidentRecord(
        id="inc-resolve-1",
        event=ev_firing,
        status=IncidentStatus.BRIEF_SENT,
        created_at=now,
    )
    await store.save_incident(rec)

    # Ingest resolved event via orchestrator
    from incidentpilot.orchestrator import IncidentOrchestrator

    orch = IncidentOrchestrator(settings=Settings(db_path=db), store=store)
    ev_resolved = IncidentEvent(
        source=AlertSource.ALERTMANAGER,
        external_id="am-11",
        fingerprint="fp-resolve-test",
        service="order-api",
        title="Order latency spike",
        is_resolved=True,
    )
    res, deduped = await orch.ingest_event(ev_resolved)
    assert res is not None
    assert res.status == IncidentStatus.RESOLVED
    assert res.resolved_at is not None
    assert res.mttr_seconds is not None
    assert any(step.stage == "auto_resolved" for step in res.timeline)


async def test_storage_metrics_and_filters(tmp_path: Path) -> None:
    db = str(tmp_path / "metrics.db")
    store = IncidentStore(db)
    await store.initialize()

    now = datetime.now(timezone.utc)
    r1 = IncidentRecord(
        id="inc-1",
        event=IncidentEvent(
            source=AlertSource.GENERIC,
            external_id="1",
            fingerprint="fp1",
            service="checkout",
            title="err 1",
            severity=Severity.CRITICAL,
        ),
        status=IncidentStatus.ROLLED_BACK,
        created_at=now,
        mttr_seconds=120.0,
    )
    r2 = IncidentRecord(
        id="inc-2",
        event=IncidentEvent(
            source=AlertSource.GENERIC,
            external_id="2",
            fingerprint="fp2",
            service="billing",
            title="err 2",
            severity=Severity.LOW,
        ),
        status=IncidentStatus.INVESTIGATING,
        created_at=now,
    )
    await store.save_incident(r1)
    await store.save_incident(r2)

    # Filter by service
    filtered_svc = await store.list_incidents(service="check")
    assert len(filtered_svc) == 1
    assert filtered_svc[0].id == "inc-1"

    # Filter by severity
    filtered_sev = await store.list_incidents(severity="low")
    assert len(filtered_sev) == 1
    assert filtered_sev[0].id == "inc-2"

    # Filter by status
    filtered_status = await store.list_incidents(status="rolled_back")
    assert len(filtered_status) == 1
    assert filtered_status[0].id == "inc-1"

    # Compute metrics
    m = await store.compute_metrics()
    assert m.total_incidents == 2
    assert m.active_incidents == 1
    assert m.resolved_incidents == 1
    assert m.avg_mttr_seconds == 120.0


def test_api_simulate_and_metrics_endpoints(tmp_path: Path) -> None:
    settings = Settings(db_path=str(tmp_path / "api_test.db"))
    app = create_app(settings=settings)

    with TestClient(app) as client:
        # Simulate a real python scenario
        resp = client.post("/api/simulate", json={"scenario": "python_checkout_error"})
        assert resp.status_code == 200
        sim_data = resp.json()
        assert sim_data["status"] == "brief_sent"
        assert sim_data["brief"]["top_candidate"] is not None
        assert "calculate_tax" in sim_data["brief"]["top_stacktrace"]["frames"][0]["function"]

        # Simulate OOM runbook scenario
        resp_oom = client.post("/api/simulate", json={"scenario": "oom_runbook"})
        assert resp_oom.status_code == 200
        sim_oom = resp_oom.json()
        assert len(sim_oom["brief"]["matched_runbooks"]) >= 1
        assert sim_oom["brief"]["matched_runbooks"][0]["id"] == "oom-killed"

        # Check metrics endpoint
        m_resp = client.get("/api/metrics")
        assert m_resp.status_code == 200
        metrics = m_resp.json()
        assert metrics["total_incidents"] == 2

        # Check filtered incident query
        query_resp = client.get("/api/incidents?severity=critical")
        assert query_resp.status_code == 200
        assert len(query_resp.json()) >= 1
