package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestBuildSlackBlocks(t *testing.T) {
	record := &models.IncidentRecord{
		ID: "inc-slack-test-1",
		Event: models.IncidentEvent{
			Service:     "checkout-api",
			Environment: "production",
			Severity:    models.SeverityCritical,
			Title:       "HTTP 500 error spike",
		},
		Status: models.StatusInvestigating,
		Brief: &models.IncidentBrief{
			Confidence:              95.0,
			ProbableCause:           "Commit 8f2a1c introduced nil pointer dereference in checkout.go:114",
			Recommendation:          "Rollback to v2.4.1",
			RollbackTarget:          "v2.4.1",
			ErrorCount15m:           42,
			Evidence:                []string{"Primary stack frame: checkout.go:114", "Git blame matches author Alice"},
			InvestigationDurationMs: 820,
		},
	}

	blocks := BuildSlackBlocks(record)
	if len(blocks) < 4 {
		t.Fatalf("expected at least 4 blocks, got %d", len(blocks))
	}

	// Verify header block
	if blocks[0]["type"] != "header" {
		t.Errorf("expected header block, got %v", blocks[0]["type"])
	}

	// Verify actions block exists with confirm_rollback
	foundActions := false
	for _, b := range blocks {
		if b["type"] == "actions" {
			foundActions = true
			elements, ok := b["elements"].([]map[string]any)
			if !ok || len(elements) == 0 {
				t.Fatalf("actions elements invalid")
			}
			btn := elements[0]
			if btn["action_id"] != "confirm_rollback" {
				t.Errorf("expected confirm_rollback action_id, got %v", btn["action_id"])
			}
			if btn["value"] != "inc-slack-test-1|v2.4.1" {
				t.Errorf("expected value 'inc-slack-test-1|v2.4.1', got %v", btn["value"])
			}
		}
	}
	if !foundActions {
		t.Error("actions block not found in active incident blocks")
	}

	// Verify rolled_back status replaces actions block
	record.Status = models.StatusRolledBack
	blocksRolledBack := BuildSlackBlocks(record)
	for _, b := range blocksRolledBack {
		if b["type"] == "actions" {
			t.Error("actions block should not be present when status is rolled_back")
		}
	}
}

func TestSendIncidentBrief(t *testing.T) {
	received := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)

		blocks, ok := payload["blocks"].([]any)
		if !ok || len(blocks) == 0 {
			t.Errorf("invalid blocks in slack webhook payload: %s", string(body))
		}

		received = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := &Client{
		WebhookURL: ts.URL,
	}

	record := &models.IncidentRecord{
		ID: "inc-slack-dispatch",
		Event: models.IncidentEvent{
			Service:     "order-processor",
			Environment: "prod",
			Severity:    models.SeverityHigh,
			Title:       "Database pool timeout",
			TriggeredAt: time.Now().UTC(),
		},
		Status: models.StatusBriefSent,
		Brief: &models.IncidentBrief{
			Confidence:     85.0,
			ProbableCause:  "Pool connection leak in worker.go",
			Recommendation: "Restart worker pods or scale pool limit",
		},
	}

	delivered, _, err := client.SendBrief(context.Background(), record)
	if err != nil {
		t.Fatalf("SendBrief failed: %v", err)
	}
	if !delivered {
		t.Error("expected SendBrief to return delivered = true")
	}
	if !received {
		t.Error("Slack webhook did not receive the payload")
	}
}
