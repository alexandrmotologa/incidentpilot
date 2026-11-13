"""Per-service routing configuration loader (services.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

import yaml

from incidentpilot.config import Settings
from incidentpilot.models import ServiceRouteConfig


def load_service_routes(config_path: str) -> dict[str, ServiceRouteConfig]:
    """Load per-service routing overrides from a YAML file if present."""
    path = Path(config_path)
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    services_raw = raw.get("services") if isinstance(raw, dict) else {}
    if not isinstance(services_raw, dict):
        return {}

    routes: dict[str, ServiceRouteConfig] = {}
    for svc_name, cfg in services_raw.items():
        if not isinstance(cfg, dict):
            continue
        routes[str(svc_name)] = ServiceRouteConfig(service=str(svc_name), **cfg)
    return routes


def resolve_settings_for_service(settings: Settings, service: str) -> Settings:
    """Return a Settings copy with per-service overrides applied if configured."""
    routes = load_service_routes(settings.services_config_path)
    route = routes.get(service)
    if route is None:
        return settings

    updates: dict[str, object] = {}
    if route.git_provider in {"local", "github"}:
        updates["git_provider"] = cast(Literal["local", "github"], route.git_provider)
    if route.local_repo_path:
        updates["local_repo_path"] = route.local_repo_path
    if route.github_repo:
        updates["github_repo"] = route.github_repo
    if route.slack_channel:
        updates["slack_channel"] = route.slack_channel
    if route.slack_webhook_url:
        updates["slack_webhook_url"] = route.slack_webhook_url
    if route.rollback_provider in {"local_git", "github_workflow", "webhook"}:
        updates["rollback_provider"] = cast(
            Literal["local_git", "github_workflow", "webhook"], route.rollback_provider
        )
    if route.rollback_webhook_url:
        updates["rollback_webhook_url"] = route.rollback_webhook_url
    if route.rollback_command:
        updates["rollback_command"] = route.rollback_command

    if not updates:
        return settings
    return settings.model_copy(update=updates)
