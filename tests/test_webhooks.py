"""Tests for webhook parsers and cryptographic signature verification."""

import hashlib
import hmac
import time

from incidentpilot.models import AlertSource, Severity
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


def test_pagerduty_v3_parser() -> None:
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "occurred_at": "2026-11-13T03:00:00Z",
            "data": {
                "id": "Q123",
                "number": 42,
                "title": "High 5xx error rate",
                "urgency": "high",
                "service": {"summary": "checkout-api"},
                "body": {"details": "panic at checkout.go:114"},
            },
        }
    }
    events = parse_pagerduty_webhook(payload)
    assert len(events) == 1
    assert events[0].source == AlertSource.PAGERDUTY
    assert events[0].service == "checkout-api"
    assert events[0].severity == Severity.HIGH
    assert "checkout.go:114" in events[0].stacktrace_hint


def test_alertmanager_v4_parser_ignores_resolved() -> None:
    payload = {
        "commonLabels": {"service": "payments"},
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "abc123",
                "labels": {"alertname": "HighLatency", "severity": "critical"},
                "annotations": {"summary": "p99 > 2s", "description": "Latency spike"},
                "startsAt": "2026-11-13T03:00:00Z",
            },
            {
                "status": "resolved",
                "fingerprint": "def456",
                "labels": {"alertname": "OldAlert"},
            },
        ],
    }
    events = parse_alertmanager_webhook(payload)
    assert len(events) == 1
    assert events[0].service == "payments"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].fingerprint == "abc123"


def test_sentry_parser_extracts_frames() -> None:
    payload = {
        "project_slug": "billing-worker",
        "data": {
            "event": {
                "event_id": "evt-99",
                "title": "ZeroDivisionError: division by zero",
                "level": "error",
                "environment": "production",
                "exception": {
                    "values": [
                        {
                            "type": "ZeroDivisionError",
                            "value": "division by zero",
                            "stacktrace": {
                                "frames": [
                                    {"filename": "app/billing.py", "lineno": 88, "function": "calc_tax"}
                                ]
                            },
                        }
                    ]
                },
            }
        },
    }
    events = parse_sentry_webhook(payload)
    assert len(events) == 1
    assert events[0].source == AlertSource.SENTRY
    assert events[0].service == "billing-worker"
    assert "app/billing.py:88" in events[0].stacktrace_hint


def test_generic_parser() -> None:
    events = parse_generic_webhook({"service": "auth", "title": "OOM", "severity": "critical"})
    assert len(events) == 1
    assert events[0].severity == Severity.CRITICAL


def test_signature_verifiers() -> None:
    body = b'{"hello":"world"}'
    secret = "topsecret"

    pd_sig = "v1=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_pagerduty_signature(body, pd_sig, secret)
    assert not verify_pagerduty_signature(body, "v1=bad", secret)

    sentry_sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_sentry_signature(body, sentry_sig, secret)
    assert not verify_sentry_signature(body, "bad", secret)

    assert verify_bearer_token("Bearer mytoken", "mytoken")
    assert not verify_bearer_token("Bearer wrong", "mytoken")

    ts = str(int(time.time()))
    basestring = f"v0:{ts}:".encode() + body
    slack_sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    assert verify_slack_signature(body, ts, slack_sig, secret)
    assert not verify_slack_signature(body, ts, "v0=bad", secret)
