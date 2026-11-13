"""Log collectors for JSONL files, Grafana Loki, and HTTP log endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import httpx

from incidentpilot.config import Settings
from incidentpilot.models import LogEntry

ERROR_LEVELS = {"ERROR", "ERR", "FATAL", "PANIC", "CRITICAL", "CRIT"}


def _parse_timestamp(raw: object) -> datetime:
    if isinstance(raw, (int, float)):
        val = float(raw)
        if val > 1e15:  # nanoseconds
            val = val / 1e9
        elif val > 1e12:  # milliseconds
            val = val / 1e3
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(raw, str) and raw.strip():
        cleaned = raw.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


class LogCollector(Protocol):
    """Interface for querying error logs within a time window."""

    async def fetch_error_logs(
        self, service: str, since: datetime, until: datetime
    ) -> list[LogEntry]: ...


class JsonlFileCollector:
    """Reads structured JSONL or plain-text log files."""

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)

    async def fetch_error_logs(
        self, service: str, since: datetime, until: datetime
    ) -> list[LogEntry]:
        if not self.file_path.exists():
            return []

        entries: list[LogEntry] = []
        content = self.file_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue

            level = str(data.get("level") or data.get("severity") or "INFO").upper()
            if level not in ERROR_LEVELS:
                continue

            entry_service = str(data.get("service") or data.get("app") or service)
            if service and entry_service != service and service != "unknown-service":
                continue

            ts = _parse_timestamp(data.get("timestamp") or data.get("ts") or data.get("time"))
            if ts < since or ts > until:
                continue

            message = str(data.get("message") or data.get("msg") or data.get("error") or "")
            stacktrace = str(data.get("stacktrace") or data.get("stack") or data.get("trace") or "")
            if not stacktrace and ("\n" in message or ".go:" in message or ".py" in message):
                stacktrace = message

            entries.append(
                LogEntry(
                    timestamp=ts,
                    level=level,
                    service=entry_service,
                    message=message,
                    trace_id=str(data.get("trace_id") or ""),
                    stacktrace=stacktrace,
                    metadata={
                        k: v
                        for k, v in data.items()
                        if k not in {"timestamp", "ts", "time", "level", "severity", "service", "app", "message", "msg", "stacktrace", "stack", "trace_id"}
                    },
                )
            )

        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries


class LokiLogCollector:
    """Queries Grafana Loki HTTP API (/loki/api/v1/query_range)."""

    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def fetch_error_logs(
        self, service: str, since: datetime, until: datetime
    ) -> list[LogEntry]:
        query = f'{{service="{service}"}} |~ "(?i)(error|fatal|panic|exception)"'
        params = {
            "query": query,
            "start": str(int(since.timestamp() * 1e9)),
            "end": str(int(until.timestamp() * 1e9)),
            "limit": "500",
            "direction": "BACKWARD",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/loki/api/v1/query_range", params=params)
            resp.raise_for_status()
            payload = resp.json()

        entries: list[LogEntry] = []
        results = (payload.get("data") or {}).get("result") or []
        for stream in results:
            labels = stream.get("stream") or {}
            for ts_ns, raw_line in stream.get("values") or []:
                ts = _parse_timestamp(int(ts_ns))
                message = raw_line
                stacktrace = ""
                level = "ERROR"
                trace_id = ""
                try:
                    parsed = json.loads(raw_line)
                    if isinstance(parsed, dict):
                        level = str(parsed.get("level") or "ERROR").upper()
                        message = str(parsed.get("message") or parsed.get("msg") or raw_line)
                        stacktrace = str(parsed.get("stacktrace") or parsed.get("stack") or "")
                        trace_id = str(parsed.get("trace_id") or "")
                except json.JSONDecodeError:
                    if "\n" in raw_line or ".go:" in raw_line or "Traceback" in raw_line:
                        stacktrace = raw_line

                entries.append(
                    LogEntry(
                        timestamp=ts,
                        level=level,
                        service=str(labels.get("service") or service),
                        message=message,
                        trace_id=trace_id,
                        stacktrace=stacktrace,
                    )
                )

        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries


class HttpLogCollector:
    """Queries a generic REST log endpoint returning JSON array or {logs: [...]}."""

    def __init__(self, endpoint_url: str, timeout: float = 15.0) -> None:
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    async def fetch_error_logs(
        self, service: str, since: datetime, until: datetime
    ) -> list[LogEntry]:
        if not self.endpoint_url:
            return []
        params = {
            "service": service,
            "since": since.isoformat(),
            "until": until.isoformat(),
            "level": "ERROR",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(self.endpoint_url, params=params)
            resp.raise_for_status()
            data = resp.json()

        raw_items = data if isinstance(data, list) else data.get("logs", [])
        entries: list[LogEntry] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            entries.append(
                LogEntry(
                    timestamp=_parse_timestamp(item.get("timestamp")),
                    level=str(item.get("level") or "ERROR").upper(),
                    service=str(item.get("service") or service),
                    message=str(item.get("message") or ""),
                    trace_id=str(item.get("trace_id") or ""),
                    stacktrace=str(item.get("stacktrace") or ""),
                )
            )
        return entries


def build_log_collector(settings: Settings) -> LogCollector:
    """Instantiate the configured log collector."""
    if settings.log_provider == "loki":
        return LokiLogCollector(settings.loki_url)
    if settings.log_provider == "http":
        return HttpLogCollector(settings.http_log_url)
    return JsonlFileCollector(settings.log_file_path)
