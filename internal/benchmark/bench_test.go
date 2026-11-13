package benchmark

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
)

func TestBenchmarkSuite(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_test.db")

	store, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	cfg := &config.Config{
		Version: "1.0.0",
	}

	report, err := RunBenchmarkSuite(context.Background(), cfg, store)
	if err != nil {
		t.Fatalf("RunBenchmarkSuite failed: %v", err)
	}

	for _, r := range report.Results {
		t.Logf("Scenario %s: passed=%v, detected=%s, expected=%s", r.Name, r.Passed, r.Detected, r.Expected)
	}
	if report.TotalScenarios != 5 {
		t.Errorf("expected 5 scenarios, got %d", report.TotalScenarios)
	}
	if report.PassedCount != 5 {
		t.Errorf("expected 5/5 passed, got %d/%d", report.PassedCount, report.TotalScenarios)
	}
	if report.Accuracy != 100.0 {
		t.Errorf("expected 100%% accuracy, got %.1f%%", report.Accuracy)
	}
}
