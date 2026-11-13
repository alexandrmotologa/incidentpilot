package runbooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestDefaultRunbooksMatching(t *testing.T) {
	// Case 1: OOMKilled in error message
	evOOM := models.IncidentEvent{
		Service:     "order-processor",
		Title:       "Pod restarted with exit code 137",
		Description: "Process was killed by OOMKilled signal",
	}
	matchesOOM := MatchRunbooks(evOOM, nil, "")
	if len(matchesOOM) == 0 {
		t.Fatal("expected OOM runbook match, got 0")
	}
	if matchesOOM[0].ID != "oom-killed" {
		t.Errorf("expected oom-killed runbook, got: %s", matchesOOM[0].ID)
	}
	if len(matchesOOM[0].Steps) < 2 {
		t.Errorf("expected operational steps, got: %v", matchesOOM[0].Steps)
	}

	// Case 2: DB pool in logs
	evDB := models.IncidentEvent{
		Service: "auth-api",
		Title:   "Slow requests and timeouts",
	}
	logsDB := []models.LogEntry{
		{Message: "failed to acquire connection from pool: timeout after 5000ms"},
	}
	matchesDB := MatchRunbooks(evDB, logsDB, "")
	if len(matchesDB) == 0 {
		t.Fatal("expected DB pool runbook match, got 0")
	}
	if matchesDB[0].ID != "db-pool-exhausted" {
		t.Errorf("expected db-pool-exhausted runbook, got: %s", matchesDB[0].ID)
	}

	// Case 3: 429 rate limit
	evRate := models.IncidentEvent{
		Service:     "payment-gateway",
		Title:       "HTTP 429 Too Many Requests from Stripe",
		Description: "Rate limit exceeded on charge endpoint",
	}
	matchesRate := MatchRunbooks(evRate, nil, "")
	if len(matchesRate) == 0 {
		t.Fatal("expected rate limit runbook match, got 0")
	}
	if matchesRate[0].ID != "upstream-rate-limit" {
		t.Errorf("expected upstream-rate-limit runbook, got: %s", matchesRate[0].ID)
	}
}

func TestCustomRunbooksYaml(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "custom-runbooks.yaml")

	yamlContent := `
runbooks:
  - id: "custom-redis-failover"
    title: "Redis Sentinel Failover In Progress"
    pattern: "(?i)(LOADING Redis is loading the dataset in memory|READONLY You can't write against a read only replica)"
    steps:
      - "Verify Sentinel quorum status using redis-cli -p 26379 sentinel masters."
      - "Wait for failover election to complete and promotion to finish."
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write custom yaml: %v", err)
	}

	ev := models.IncidentEvent{
		Service:     "cache-service",
		Title:       "Write failed",
		Description: "READONLY You can't write against a read only replica",
	}
	matches := MatchRunbooks(ev, nil, yamlPath)
	if len(matches) == 0 {
		t.Fatal("expected custom runbook match, got 0")
	}
	if matches[0].ID != "custom-redis-failover" {
		t.Errorf("expected custom-redis-failover, got %s", matches[0].ID)
	}
}
