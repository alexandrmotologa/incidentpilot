"""Tests for per-service routing configuration resolution."""

from incidentpilot.config import Settings
from incidentpilot.routing import load_service_routes, resolve_settings_for_service


def test_load_and_resolve_service_routing(tmp_path) -> None:
    cfg_file = tmp_path / "services.yaml"
    cfg_file.write_text(
        """
services:
  payment-service:
    git_provider: github
    github_repo: org/payments
    slack_channel: "#payments-oncall"
    rollback_provider: github_workflow
""",
        encoding="utf-8",
    )
    base_settings = Settings(
        git_provider="local",
        slack_channel="#general-alerts",
        services_config_path=str(cfg_file),
    )
    routes = load_service_routes(str(cfg_file))
    assert "payment-service" in routes

    resolved = resolve_settings_for_service(base_settings, "payment-service")
    assert resolved.git_provider == "github"
    assert resolved.github_repo == "org/payments"
    assert resolved.slack_channel == "#payments-oncall"
    assert resolved.rollback_provider == "github_workflow"

    # Fallback to base settings for unspecified services
    fallback = resolve_settings_for_service(base_settings, "other-service")
    assert fallback.git_provider == "local"
    assert fallback.slack_channel == "#general-alerts"
