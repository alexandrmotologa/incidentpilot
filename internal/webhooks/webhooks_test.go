package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestWebhooksParsersAndSecurity(t *testing.T) {
	// PagerDuty V3
	pdPayload := []byte(`{
		"event": {
			"event_type": "incident.triggered",
			"occurred_at": "2026-11-13T03:00:00Z",
			"data": {
				"id": "PD-123",
				"number": 42,
				"title": "High 5xx rate",
				"urgency": "high",
				"service": {"summary": "checkout-api"},
				"body": {"details": "panic at checkout.go:114"}
			}
		}
	}`)
	pdEvents, err := ParsePagerDutyWebhook(pdPayload)
	if err != nil || len(pdEvents) != 1 {
		t.Fatalf("ParsePagerDutyWebhook failed: %v", err)
	}
	if pdEvents[0].Service != "checkout-api" || pdEvents[0].Severity != models.SeverityHigh {
		t.Errorf("unexpected pd event: %+v", pdEvents[0])
	}

	// Alertmanager v4
	amPayload := []byte(`{
		"commonLabels": {"service": "payments"},
		"alerts": [
			{
				"status": "firing",
				"fingerprint": "fp1",
				"labels": {"alertname": "LatencyHigh", "severity": "critical"},
				"annotations": {"summary": "p99 > 2s"}
			},
			{
				"status": "resolved",
				"fingerprint": "fp2",
				"labels": {"alertname": "OldAlert"}
			}
		]
	}`)
	amEvents, err := ParseAlertmanagerWebhook(amPayload)
	if err != nil || len(amEvents) != 2 {
		t.Fatalf("ParseAlertmanagerWebhook failed: %v", err)
	}
	if amEvents[0].IsResolved || !amEvents[1].IsResolved {
		t.Errorf("expected amEvents[1] to be resolved")
	}

	// Sentry
	sentryPayload := []byte(`{
		"project_slug": "billing-worker",
		"data": {
			"event": {
				"event_id": "evt-1",
				"title": "ZeroDivisionError: division by zero",
				"level": "error",
				"datetime": "2026-11-13T03:00:00Z",
				"exception": {
					"values": [{
						"type": "ZeroDivisionError",
						"value": "division by zero",
						"stacktrace": {
							"frames": [{"filename": "app/billing.py", "lineno": 88, "function": "calc_tax"}]
						}
					}]
				}
			}
		}
	}`)
	sentryEvents, err := ParseSentryWebhook(sentryPayload)
	if err != nil || len(sentryEvents) != 1 {
		t.Fatalf("ParseSentryWebhook failed: %v", err)
	}
	if sentryEvents[0].Service != "billing-worker" {
		t.Errorf("unexpected sentry event: %+v", sentryEvents[0])
	}

	// Datadog
	ddPayload := []byte(`{
		"id": 9999,
		"title": "CPU utilization alert",
		"alert_type": "error",
		"tags": "service:media-transcoder,env:production"
	}`)
	ddEvents, err := ParseDatadogWebhook(ddPayload)
	if err != nil || len(ddEvents) != 1 {
		t.Fatalf("ParseDatadogWebhook failed: %v", err)
	}
	if ddEvents[0].Service != "media-transcoder" {
		t.Errorf("unexpected datadog event: %+v", ddEvents[0])
	}

	// Signature verification
	secret := "topsecret"
	body := []byte(`{"test":true}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	if !VerifyPagerDutySignature(body, "v1="+sigHex, secret) {
		t.Error("VerifyPagerDutySignature failed")
	}
	if !VerifySentrySignature(body, sigHex, secret) {
		t.Error("VerifySentrySignature failed")
	}
	if !VerifyBearerToken("Bearer valid-token", "valid-token") {
		t.Error("VerifyBearerToken failed")
	}
	if !VerifyDatadogToken("dd-secret-token", "dd-secret-token") {
		t.Error("VerifyDatadogToken failed")
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	basestring := fmt.Sprintf("v0:%s:%s", ts, string(body))
	macSlack := hmac.New(sha256.New, []byte(secret))
	macSlack.Write([]byte(basestring))
	slackSig := "v0=" + hex.EncodeToString(macSlack.Sum(nil))
	if !VerifySlackSignature(body, ts, slackSig, secret, 300) {
		t.Error("VerifySlackSignature failed")
	}
}
