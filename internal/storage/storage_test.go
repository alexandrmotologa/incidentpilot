package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestStorageOperationsAndMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	mttr := 120.5

	r1 := &models.IncidentRecord{
		ID: "inc-test-1",
		Event: models.IncidentEvent{
			Source:      models.SourcePagerDuty,
			Fingerprint: "fp-test-1",
			Service:     "checkout-api",
			Title:       "High 5xx rate",
			Severity:    models.SeverityCritical,
			TriggeredAt: now,
		},
		Status:      models.StatusRolledBack,
		AlertCount:  1,
		CreatedAt:   now,
		UpdatedAt:   now,
		MTTRSeconds: &mttr,
		Brief: &models.IncidentBrief{
			Confidence: 95.0,
			TopCandidate: &models.CorrelationCandidate{
				Score: 95.0,
			},
			InvestigationDurationMs: 850,
		},
	}

	if err := store.SaveIncident(ctx, r1); err != nil {
		t.Fatalf("SaveIncident failed: %v", err)
	}

	fetched, err := store.GetIncident(ctx, "inc-test-1")
	if err != nil || fetched == nil {
		t.Fatalf("GetIncident failed: %v", err)
	}
	if fetched.Event.Service != "checkout-api" {
		t.Errorf("expected checkout-api, got: %s", fetched.Event.Service)
	}

	// Filter by service
	list, err := store.ListIncidents(ctx, 10, "checkout", "", "")
	if err != nil || len(list) != 1 {
		t.Errorf("ListIncidents filter failed: %v, count: %d", err, len(list))
	}

	// Active fingerprint deduplication lookup
	active, err := store.FindActiveByFingerprint(ctx, "fp-test-1", 300)
	// r1 is rolled_back, so should be inactive
	if err != nil || active != nil {
		t.Errorf("expected no active incident for rolled_back status, got %v", active)
	}

	// Save rollback audit record
	rb := &models.RollbackRecord{
		ID:            "rb-test-1",
		IncidentID:    "inc-test-1",
		TargetVersion: "v2.4.1",
		Provider:      "local_git",
		Status:        "succeeded",
		RequestedBy:   "tester",
		ExecutedAt:    now,
		Output:        "Checked out v2.4.1",
	}
	if err := store.SaveRollback(ctx, rb); err != nil {
		t.Fatalf("SaveRollback failed: %v", err)
	}

	// Compute metrics
	metrics, err := store.ComputeMetrics(ctx)
	if err != nil {
		t.Fatalf("ComputeMetrics failed: %v", err)
	}
	if metrics.TotalIncidents != 1 || metrics.ResolvedIncidents != 1 {
		t.Errorf("unexpected metrics: %+v", metrics)
	}
	if metrics.AvgMTTRSeconds == nil || *metrics.AvgMTTRSeconds != 120.5 {
		t.Errorf("expected avg mttr 120.5, got: %v", metrics.AvgMTTRSeconds)
	}
}
