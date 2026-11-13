"""Tests for the operational runbook matcher."""

from incidentpilot.models import AlertSource, IncidentEvent, LogEntry
from incidentpilot.runbooks import match_runbooks


def test_match_built_in_oom_runbook() -> None:
    event = IncidentEvent(
        source=AlertSource.ALERTMANAGER,
        external_id="am-1",
        fingerprint="fp-oom",
        service="worker-pool",
        title="Pod terminated with exit code 137 (OOMKilled)",
    )
    logs = [
        LogEntry(
            timestamp=event.triggered_at,
            service="worker-pool",
            message="Out of memory: memory limit reached for cgroup",
        )
    ]
    matches = match_runbooks(event, logs)
    assert len(matches) >= 1
    assert matches[0].id == "oom-killed"
    assert "kubectl top pods" in matches[0].steps[0]


def test_match_custom_yaml_runbook(tmp_path) -> None:
    custom_yaml = tmp_path / "custom_runbooks.yaml"
    custom_yaml.write_text(
        """
runbooks:
  - id: custom-dns-error
    title: DNS Resolution Failure
    pattern: "(SERVFAIL|NXDOMAIN|i/o timeout resolving)"
    steps:
      - "Check CoreDNS pod status"
""",
        encoding="utf-8",
    )
    event = IncidentEvent(
        source=AlertSource.GENERIC,
        external_id="gen-1",
        fingerprint="fp-dns",
        service="gateway",
        title="Connection failed",
        description="i/o timeout resolving auth.internal.corp",
    )
    matches = match_runbooks(event, [], config_path=str(custom_yaml))
    assert len(matches) == 1
    assert matches[0].id == "custom-dns-error"
    assert matches[0].steps == ["Check CoreDNS pod status"]
