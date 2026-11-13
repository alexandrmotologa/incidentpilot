"""Cryptographic signature and token verification for inbound webhooks."""

from __future__ import annotations

import hashlib
import hmac
import time


def verify_pagerduty_signature(body: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify PagerDuty V3 X-PagerDuty-Signature header (v1=<hex_hmac_sha256>)."""
    if not secret:
        return True
    if not signature_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    candidates = [part.strip() for part in signature_header.split(",")]
    for candidate in candidates:
        if candidate.startswith("v1="):
            provided = candidate[3:]
            if hmac.compare_digest(provided, expected):
                return True
    return False


def verify_sentry_signature(body: bytes, signature_header: str | None, client_secret: str) -> bool:
    """Verify Sentry Sentry-Hook-Signature header (HMAC-SHA256 hex digest)."""
    if not client_secret:
        return True
    if not signature_header:
        return False
    expected = hmac.new(client_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header.strip(), expected)


def verify_bearer_token(auth_header: str | None, expected_token: str) -> bool:
    """Verify Authorization: Bearer <token> header for Alertmanager webhooks."""
    if not expected_token:
        return True
    if not auth_header or not auth_header.startswith("Bearer "):
        return False
    provided = auth_header[7:].strip()
    return hmac.compare_digest(provided, expected_token)


def verify_slack_signature(
    body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    signing_secret: str,
    max_age_seconds: int = 300,
) -> bool:
    """Verify Slack request signature (v0=hmac_sha256('v0:ts:body'))."""
    if not signing_secret:
        return True
    if not timestamp_header or not signature_header:
        return False
    try:
        ts = int(timestamp_header)
    except ValueError:
        return False
    if abs(time.time() - ts) > max_age_seconds:
        return False
    basestring = f"v0:{timestamp_header}:".encode("utf-8") + body
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), basestring, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature_header.strip(), expected)
