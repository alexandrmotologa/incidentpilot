package tui

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestRenderTopSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "tui_test.db")

	store, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	// Seed with an incident
	now := time.Now().UTC()
	inc := &models.IncidentRecord{
		ID: "inc-tui-1",
		Event: models.IncidentEvent{
			Service:     "checkout-service",
			Severity:    models.SeverityCritical,
			TriggeredAt: now,
		},
		Status:    models.StatusVerifiedHealthy,
		CreatedAt: now,
		UpdatedAt: now,
		Brief: &models.IncidentBrief{
			RollbackTarget: "v2.4.1",
		},
	}
	_ = store.SaveIncident(context.Background(), inc)

	if err := RenderTopSnapshot(context.Background(), store, dbPath); err != nil {
		t.Fatalf("RenderTopSnapshot failed: %v", err)
	}
}
