package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/collectors"
	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/orchestrator"
	"github.com/alexandrmotologa/incidentpilot/internal/rollback"
	"github.com/alexandrmotologa/incidentpilot/internal/slack"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func setupTestServer(t *testing.T) (*Server, *storage.Store, *orchestrator.Orchestrator) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_server.db")

	store, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{
		Version:            "1.0.0",
		Port:               8080,
		DedupWindowSeconds: 300,
	}

	logColl := &collectors.JsonlLogCollector{FilePath: filepath.Join(tmpDir, "logs.jsonl")}
	gitProv := &collectors.LocalGitProvider{RepoPath: tmpDir}
	slackCli := &slack.Client{}
	rbExec := &rollback.Executor{Provider: "local_git", LocalRepoPath: tmpDir}

	orch := orchestrator.NewOrchestrator(cfg, store, logColl, gitProv, slackCli, rbExec)
	srv := NewServer(cfg, store, orch)
	return srv, store, orch
}

func TestHealthCheck(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	var res map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}
	if res["status"] != "ok" || res["runtime"] != "go" {
		t.Errorf("unexpected healthz payload: %+v", res)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var metrics models.SreMetrics
	if err := json.NewDecoder(rec.Body).Decode(&metrics); err != nil {
		t.Fatalf("failed to decode SreMetrics: %v", err)
	}
	if metrics.TotalIncidents != 0 {
		t.Errorf("expected 0 total incidents, got %d", metrics.TotalIncidents)
	}
}

func TestGenericWebhookAndIncidentLifecycle(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	// Ingest generic webhook with sync=true to wait for investigation
	webhookPayload := map[string]any{
		"service":     "checkout-service",
		"environment": "production",
		"title":       "HTTP 500 error spike",
		"description": "panic: nil pointer dereference at checkout.go:114",
		"severity":    "critical",
	}
	body, _ := json.Marshal(webhookPayload)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/generic?sync=true", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from generic webhook, got %d (%s)", rec.Code, rec.Body.String())
	}

	var ingestResult struct {
		Accepted  int              `json:"accepted"`
		Incidents []map[string]any `json:"incidents"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ingestResult); err != nil {
		t.Fatalf("failed to decode ingest result: %v", err)
	}
	if len(ingestResult.Incidents) == 0 {
		t.Fatal("expected at least 1 incident in ingest result")
	}
	incID, ok := ingestResult.Incidents[0]["incident_id"].(string)
	if !ok || incID == "" {
		t.Fatalf("missing incident_id in response: %+v", ingestResult.Incidents[0])
	}

	// GET /api/incidents
	listReq := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	listRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/incidents, got %d", listRec.Code)
	}
	var incidents []models.IncidentRecord
	_ = json.NewDecoder(listRec.Body).Decode(&incidents)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}

	// GET /api/incidents/{id}
	getReq := httptest.NewRequest(http.MethodGet, "/api/incidents/"+incID, nil)
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/incidents/%s, got %d", incID, getRec.Code)
	}
	var fetched models.IncidentRecord
	_ = json.NewDecoder(getRec.Body).Decode(&fetched)
	if fetched.ID != incID {
		t.Errorf("expected ID %s, got %s", incID, fetched.ID)
	}

	// GET /api/incidents/{id}/postmortem.md
	pmReq := httptest.NewRequest(http.MethodGet, "/api/incidents/"+incID+"/postmortem.md", nil)
	pmRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pmRec, pmReq)

	if pmRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for postmortem.md, got %d", pmRec.Code)
	}
	pmBody := pmRec.Body.String()
	if !strings.Contains(pmBody, incID) || !strings.Contains(pmBody, "checkout-service") {
		t.Errorf("expected postmortem markdown to contain incident ID and service, got: %s", pmBody)
	}

	// POST /api/incidents/{id}/dismiss
	dismissReq := httptest.NewRequest(http.MethodPost, "/api/incidents/"+incID+"/dismiss", bytes.NewBufferString(`{"actor":"tester"}`))
	dismissRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(dismissRec, dismissReq)

	if dismissRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from dismiss, got %d", dismissRec.Code)
	}
	var dismissed models.IncidentRecord
	_ = json.NewDecoder(dismissRec.Body).Decode(&dismissed)
	if dismissed.Status != models.StatusDismissed {
		t.Errorf("expected dismissed status, got %s", dismissed.Status)
	}
}

func TestSimulateEndpoint(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	simBody := bytes.NewBufferString(`{"scenario":"go_nil_pointer"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/simulate", simBody)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/simulate, got %d (%s)", rec.Code, rec.Body.String())
	}

	var recResult models.IncidentRecord
	if err := json.NewDecoder(rec.Body).Decode(&recResult); err != nil {
		t.Fatalf("failed to parse simulation response: %v", err)
	}
	if recResult.Brief == nil {
		t.Fatal("expected non-nil brief from simulation")
	}
	if recResult.Brief.RollbackTarget == "" {
		t.Error("expected non-empty rollback target from simulation")
	}
}

func TestSlackInteractivityDismiss(t *testing.T) {
	srv, store, _ := setupTestServer(t)

	// Create an open incident
	now := time.Now().UTC()
	inc := &models.IncidentRecord{
		ID: "inc-slack-dismiss-1",
		Event: models.IncidentEvent{
			Service:     "auth-service",
			TriggeredAt: now,
		},
		Status:    models.StatusInvestigating,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.SaveIncident(t.Context(), inc)

	slackPayload := `{
		"user": {"username": "oncall-bob"},
		"response_url": "https://hooks.slack.com/actions/test",
		"actions": [
			{"action_id": "dismiss_incident", "value": "inc-slack-dismiss-1"}
		]
	}`

	form := "payload=" + strings.ReplaceAll(slackPayload, "\n", "")
	req := httptest.NewRequest(http.MethodPost, "/integrations/slack/actions", io.NopCloser(strings.NewReader(form)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from slack actions, got %d (%s)", rec.Code, rec.Body.String())
	}

	updated, _ := store.GetIncident(t.Context(), "inc-slack-dismiss-1")
	if updated == nil || updated.Status != models.StatusDismissed {
		t.Errorf("expected incident to be dismissed, got %+v", updated)
	}
}
