"""SQLite persistence layer for incidents, timelines, and rollbacks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite

from incidentpilot.models import (
    IncidentRecord,
    IncidentStatus,
    RollbackRecord,
)


class IncidentStore:
    """Async SQLite store for IncidentPilot."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._initialized = False

    async def initialize(self) -> None:
        """Create database directory and schema if needed."""
        if self._initialized:
            return
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    service TEXT NOT NULL,
                    status TEXT NOT NULL,
                    alert_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                """
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint, created_at);"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);"
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS rollbacks (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    target_version TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    output TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT ''
                );
                """
            )
            await db.commit()
        self._initialized = True

    async def save_incident(self, record: IncidentRecord) -> None:
        """Insert or update an incident record."""
        await self.initialize()
        record.updated_at = datetime.now(timezone.utc)
        payload = record.model_dump_json()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO incidents (
                    id, fingerprint, service, status, alert_count, created_at, updated_at, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    alert_count = excluded.alert_count,
                    updated_at = excluded.updated_at,
                    record_json = excluded.record_json;
                """,
                (
                    record.id,
                    record.event.fingerprint,
                    record.event.service,
                    record.status.value,
                    record.alert_count,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                    payload,
                ),
            )
            await db.commit()

    async def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Fetch a single incident by ID."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT record_json FROM incidents WHERE id = ?;",
                (incident_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return IncidentRecord.model_validate_json(row[0])

    async def list_incidents(self, limit: int = 50, service: str | None = None) -> list[IncidentRecord]:
        """List recent incidents ordered newest first."""
        await self.initialize()
        query = "SELECT record_json FROM incidents"
        params: list[object] = []
        if service:
            query += " WHERE service = ?"
            params.append(service)
        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [IncidentRecord.model_validate_json(row[0]) for row in rows]

    async def find_active_by_fingerprint(
        self, fingerprint: str, window_seconds: int
    ) -> IncidentRecord | None:
        """Find an active incident with matching fingerprint within the deduplication window."""
        await self.initialize()
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        inactive = (IncidentStatus.RESOLVED.value, IncidentStatus.DISMISSED.value)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT record_json FROM incidents
                WHERE fingerprint = ?
                  AND created_at >= ?
                  AND status NOT IN (?, ?)
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (fingerprint, cutoff, inactive[0], inactive[1]),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return IncidentRecord.model_validate_json(row[0])

    async def save_rollback(self, rollback: RollbackRecord) -> None:
        """Persist a rollback execution audit record."""
        await self.initialize()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO rollbacks (
                    id, incident_id, target_version, provider, status,
                    requested_by, executed_at, output, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    output = excluded.output,
                    error = excluded.error;
                """,
                (
                    rollback.id,
                    rollback.incident_id,
                    rollback.target_version,
                    rollback.provider,
                    rollback.status,
                    rollback.requested_by,
                    rollback.executed_at.isoformat(),
                    rollback.output,
                    rollback.error,
                ),
            )
            await db.commit()
