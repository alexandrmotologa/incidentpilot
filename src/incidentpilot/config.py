"""Configuration management for IncidentPilot."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_prefix="INCIDENTPILOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 8080
    db_path: str = "./data/incidentpilot.db"
    investigation_timeout_seconds: int = 55
    log_window_minutes: int = 15
    dedup_window_seconds: int = 300

    # Webhook verification
    pagerduty_webhook_secret: str = ""
    sentry_client_secret: str = ""
    alertmanager_bearer_token: str = ""

    # Log collector
    log_provider: Literal["jsonl", "loki", "http"] = "jsonl"
    log_file_path: str = "./data/service.log.jsonl"
    loki_url: str = "http://localhost:3100"
    http_log_url: str = ""

    # Git & deployment collector
    git_provider: Literal["local", "github"] = "local"
    local_repo_path: str = "."
    github_token: str = ""
    github_repo: str = ""
    git_lookback_hours: int = 48

    # Optional LLM synthesis
    llm_api_url: str = "https://api.openai.com/v1/chat/completions"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # Slack integration
    slack_webhook_url: str = ""
    slack_bot_token: str = ""
    slack_channel: str = ""
    slack_signing_secret: str = ""

    # Rollback executor
    rollback_provider: Literal["local_git", "github_workflow", "webhook"] = "local_git"
    rollback_webhook_url: str = ""
    rollback_webhook_secret: str = ""
    github_rollback_workflow: str = "rollback.yml"
    rollback_command: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
