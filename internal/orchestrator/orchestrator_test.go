package orchestrator

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/rollback"
	"github.com/alexandrmotologa/incidentpilot/internal/slack"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type mockGitProvider struct {
	commits     []models.CommitInfo
	deployments []models.DeploymentInfo
	blameSHA    string
}

func (m *mockGitProvider) FetchRecentCommits(ctx context.Context, since time.Time, limit int) ([]models.CommitInfo, error) {
	return m.commits, nil
}

func (m *mockGitProvider) FetchRecentDeployments(ctx context.Context, env string, limit int) ([]models.DeploymentInfo, error) {
	return m.deployments, nil
}

func (m *mockGitProvider) BlameLine(ctx context.Context, filePath string, line int) (string, error) {
	return m.blameSHA, nil
}

type mockLogCollector struct {
	logs []models.LogEntry
}

func (m *mockLogCollector) FetchErrorLogs(ctx context.Context, service string, since, until time.Time) ([]models.LogEntry, error) {
	return m.logs, nil
}

func TestOrchestratorEndToEndInvestigation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "orch_test.db")

	store, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	cfg := &config.Config{
		Version:                 "1.0.0",
		InvestigationTimeoutSec: 10,
		DedupWindowSeconds:      300,
	}

	now := time.Now().UTC()
	logs := []models.LogEntry{
		{
			Timestamp:  now.Add(-2 * time.Minute),
			Level:      "ERROR",
			Service:    "checkout-service",
			Message:    "panic: runtime error: invalid memory address or nil pointer dereference",
			Stacktrace: "panic: runtime error: nil pointer dereference\ngithub.com/acme/checkout/pkg/checkout.Charge(0x0)\n\t/app/pkg/checkout/checkout.go:114 +0x2c\n",
		},
	}

	commits := []models.CommitInfo{
		{
			SHA:       "8f2a1c9999999999999999999999999999999999",
			ShortSHA:  "8f2a1c9",
			Author:    "Alice Dev",
			Message:   "refactor checkout charge method",
			Timestamp: now.Add(-15 * time.Minute),
			Files: []models.FileDiff{
				{
					Path: "pkg/checkout/checkout.go",
					ChangedLineRanges: []models.LineRange{
						{Start: 110, End: 125},
					},
				},
			},
		},
	}

	deployments := []models.DeploymentInfo{
		{
			Version:   "v2.4.2",
			CommitSHA: "8f2a1c9999999999999999999999999999999999",
		},
		{
			Version:   "v2.4.1",
			CommitSHA: "1a2b3c4444444444444444444444444444444444",
		},
	}

	mockGit := &mockGitProvider{
		commits:     commits,
		deployments: deployments,
		blameSHA:    "8f2a1c9",
	}
	mockLogs := &mockLogCollector{logs: logs}
	slackCli := &slack.Client{}
	rbExec := &rollback.Executor{Provider: "local_git", LocalRepoPath: tmpDir}

	orch := NewOrchestrator(cfg, store, mockLogs, mockGit, slackCli, rbExec)

	ev := models.IncidentEvent{
		Source:         models.SourcePagerDuty,
		ExternalID:     "pd-alert-1",
		Fingerprint:    "fp-checkout-panic",
		Service:        "checkout-service",
		Environment:    "production",
		Title:          "HTTP 500 error spike",
		Description:    "Service health check failing",
		Severity:       models.SeverityCritical,
		TriggeredAt:    now,
		StacktraceHint: logs[0].Stacktrace,
	}

	ctx := context.Background()
	rec, deduped, err := orch.IngestEvent(ctx, ev, true)
	if err != nil {
		t.Fatalf("IngestEvent failed: %v", err)
	}
	if deduped {
		t.Error("expected first alert not to be deduped")
	}
	if rec.Brief == nil {
		t.Fatal("expected brief to be generated synchronously")
	}

	// Verify correlation results
	if rec.Brief.RollbackTarget != "v2.4.1" {
		t.Errorf("expected rollback target v2.4.1, got %q", rec.Brief.RollbackTarget)
	}
	if rec.Brief.TopCandidate == nil || rec.Brief.TopCandidate.Commit.ShortSHA != "8f2a1c9" {
		t.Errorf("expected suspect commit 8f2a1c9, got %+v", rec.Brief.TopCandidate)
	}
	if rec.Brief.Confidence < 80.0 {
		t.Errorf("expected confidence >= 80, got %f", rec.Brief.Confidence)
	}

	// Verify Postmortem markdown generation
	postmortem := GeneratePostmortemMarkdown(rec)
	if !strings.Contains(postmortem, rec.ID) || !strings.Contains(postmortem, "v2.4.1") {
		t.Errorf("postmortem markdown missing incident info: %s", postmortem)
	}

	// Verify Dismissal
	dismissed, err := orch.DismissIncident(ctx, rec.ID, "oncall-lead")
	if err != nil {
		t.Fatalf("DismissIncident failed: %v", err)
	}
	if dismissed.Status != models.StatusDismissed {
		t.Errorf("expected status dismissed, got: %s", dismissed.Status)
	}
}

func TestHealthVerificationLoop(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "health_test.db")
	store, _ := storage.NewStore(dbPath)
	defer store.Close()

	cfg := &config.Config{
		Version:                "1.0.0",
		HealthCheckDurationSec: 1,
	}

	mockLogs := &mockLogCollector{logs: nil} // 0 logs post rollback
	mockGit := &mockGitProvider{}
	slackCli := &slack.Client{}
	rbExec := &rollback.Executor{Provider: "local_git", LocalRepoPath: tmpDir, RollbackCommand: "whoami"}

	orch := NewOrchestrator(cfg, store, mockLogs, mockGit, slackCli, rbExec)
	orch.SetSyncHealthCheck(true)

	now := time.Now().UTC()
	inc := &models.IncidentRecord{
		ID: "inc-health-check",
		Event: models.IncidentEvent{
			Service:     "checkout-api",
			Environment: "production",
			TriggeredAt: now,
		},
		Status:    models.StatusInvestigating,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.SaveIncident(context.Background(), inc)

	// Trigger rollback with sync health check
	rec, rb, err := orch.TriggerRollback(context.Background(), inc.ID, "v2.4.1", "tester")
	if err != nil || rb == nil {
		t.Fatalf("TriggerRollback failed: %v", err)
	}

	// Should transition from mitigating to verified_healthy
	if rec.Status != models.StatusVerifiedHealthy {
		t.Errorf("expected StatusVerifiedHealthy, got %s", rec.Status)
	}
	if rec.HealthVerification == nil || rec.HealthVerification.Status != "healthy" {
		t.Errorf("expected healthy verification, got %+v", rec.HealthVerification)
	}

	// Now test escalation when errors persist
	mockLogs.logs = []models.LogEntry{{Message: "persisting 500 error"}}
	incFail := &models.IncidentRecord{
		ID: "inc-health-fail",
		Event: models.IncidentEvent{
			Service:     "checkout-api",
			Environment: "production",
			TriggeredAt: now,
		},
		Status:    models.StatusInvestigating,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.SaveIncident(context.Background(), incFail)

	recFail, _, _ := orch.TriggerRollback(context.Background(), incFail.ID, "v2.4.1", "tester")
	if recFail.Status != models.StatusEscalated {
		t.Errorf("expected StatusEscalated when errors persist, got %s", recFail.Status)
	}
	if recFail.HealthVerification == nil || recFail.HealthVerification.Status != "unhealthy" {
		t.Errorf("expected unhealthy verification, got %+v", recFail.HealthVerification)
	}
}

func TestAutoRollbackGuardrails(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "guardrail_test.db")
	store, _ := storage.NewStore(dbPath)
	defer store.Close()

	spike := 10.0
	cfg := &config.Config{
		Version: "1.0.0",
		Services: []config.ServiceConfig{
			{
				Name: "payment-api",
				Mitigation: config.MitigationConfig{
					AutoRollback: models.AutoRollbackPolicy{
						Enabled:       true,
						Environments:  []string{"staging"},
						MinConfidence: 90.0,
						MinSpikeRatio: 5.0,
					},
				},
			},
		},
	}

	orch := NewOrchestrator(cfg, store, nil, nil, nil, nil)

	// Case 1: Environment is "production", allowed is only "staging" -> guardrail skips
	recProd := &models.IncidentRecord{
		ID: "inc-prod-skip",
		Event: models.IncidentEvent{
			Service:     "payment-api",
			Environment: "production",
		},
		Status: models.StatusBriefSent,
	}
	brief := &models.IncidentBrief{
		Confidence:      95.0,
		RollbackTarget:  "v1.0.0",
		ErrorSpikeRatio: &spike,
	}
	orch.evaluateAutoRollbackPolicy(context.Background(), recProd, brief)

	if len(recProd.Timeline) == 0 || recProd.Timeline[0].Stage != "guardrail_check_skipped" {
		t.Errorf("expected guardrail_check_skipped for production environment, got %+v", recProd.Timeline)
	}

	// Case 2: Environment is "staging" -> guardrails pass
	recStaging := &models.IncidentRecord{
		ID: "inc-staging-pass",
		Event: models.IncidentEvent{
			Service:     "payment-api",
			Environment: "staging",
		},
		Status: models.StatusBriefSent,
	}
	orch.evaluateAutoRollbackPolicy(context.Background(), recStaging, brief)
	if len(recStaging.Timeline) == 0 || recStaging.Timeline[0].Stage != "auto_rollback_triggered" {
		t.Errorf("expected auto_rollback_triggered, got %+v", recStaging.Timeline)
	}
}
