package correlator

import (
	"strings"
	"testing"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestPathsMatch(t *testing.T) {
	tests := []struct {
		frameFile  string
		diffPath   string
		wantMatch  bool
		wantSuffix bool
	}{
		{"pkg/checkout/checkout.go", "pkg/checkout/checkout.go", true, true},
		{"/app/pkg/checkout/checkout.go", "pkg/checkout/checkout.go", true, true},
		{"pkg/checkout/checkout.go", "checkout.go", true, true},
		{"other/path/checkout.go", "different/pkg/checkout.go", true, false}, // basename only
		{"pkg/orders/orders.go", "pkg/checkout/checkout.go", false, false},
		{"", "pkg/checkout/checkout.go", false, false},
	}

	for _, tt := range tests {
		m, s := pathsMatch(tt.frameFile, tt.diffPath)
		if m != tt.wantMatch || s != tt.wantSuffix {
			t.Errorf("pathsMatch(%q, %q) = (%v, %v); want (%v, %v)",
				tt.frameFile, tt.diffPath, m, s, tt.wantMatch, tt.wantSuffix)
		}
	}
}

func TestSelectRollbackTarget(t *testing.T) {
	suspect := &models.CommitInfo{
		SHA:      "8f2a1c9999999999999999999999999999999999",
		ShortSHA: "8f2a1c9",
	}

	// Case 1: Multiple deployments, latest matches suspect commit -> pick previous deployment
	deps := []models.DeploymentInfo{
		{Version: "v2.4.2", CommitSHA: "8f2a1c9999999999999999999999999999999999", Environment: "prod"},
		{Version: "v2.4.1", CommitSHA: "1a2b3c4444444444444444444444444444444444", Environment: "prod"},
	}
	target := SelectRollbackTarget(deps, suspect)
	if target != "v2.4.1" {
		t.Errorf("expected v2.4.1, got %q", target)
	}

	// Case 2: No deployments, fallback to commit~1
	target2 := SelectRollbackTarget(nil, suspect)
	if target2 != "8f2a1c9~1" {
		t.Errorf("expected 8f2a1c9~1, got %q", target2)
	}

	// Case 3: Single deployment not matching suspect
	depsSingle := []models.DeploymentInfo{
		{Version: "v2.3.0", CommitSHA: "0000000000000000000000000000000000000000", Environment: "prod"},
	}
	target3 := SelectRollbackTarget(depsSingle, suspect)
	if target3 != "v2.3.0" {
		t.Errorf("expected v2.3.0, got %q", target3)
	}
}

func TestComputeSpikeRatio(t *testing.T) {
	if ratio := computeSpikeRatio(0, 0); ratio != nil {
		t.Errorf("expected nil ratio for 0, 0, got %v", *ratio)
	}

	// 30 current errors in 15m, 30 baseline errors across 45m (10 per 15m) -> 3.0x spike
	ratio := computeSpikeRatio(30, 30)
	if ratio == nil || *ratio != 3.0 {
		t.Errorf("expected 3.0, got %v", ratio)
	}

	// 15 current errors, zero baseline errors -> 15.0x
	ratioZero := computeSpikeRatio(15, 0)
	if ratioZero == nil || *ratioZero != 15.0 {
		t.Errorf("expected 15.0, got %v", ratioZero)
	}
}

func TestCorrelateIncidentScoring(t *testing.T) {
	event := models.IncidentEvent{
		Service:     "checkout-service",
		Title:       "HTTP 500 error spike in checkout",
		Description: "Panic nil pointer dereference",
		Severity:    models.SeverityCritical,
	}

	st := &models.ParsedStackTrace{
		ErrorType:    "panic",
		ErrorMessage: "nil pointer dereference",
		Language:     "go",
		Frames: []models.StackFrame{
			{File: "pkg/checkout/checkout.go", Line: 114, Function: "Charge"},
		},
	}

	commits := []models.CommitInfo{
		{
			SHA:      "8f2a1c9999999999999999999999999999999999",
			ShortSHA: "8f2a1c9",
			Author:   "Dev One",
			Message:  "fix nil pointer check in checkout",
			Timestamp: time.Now().UTC().Add(-10 * time.Minute),
			Files: []models.FileDiff{
				{
					Path: "pkg/checkout/checkout.go",
					ChangedLineRanges: []models.LineRange{
						{Start: 110, End: 120},
					},
					Patch: "@@ -110,5 +110,6 @@ ...",
				},
			},
		},
		{
			SHA:      "abcdef1111111111111111111111111111111111",
			ShortSHA: "abcdef1",
			Author:   "Dev Two",
			Message:  "update README docs",
			Timestamp: time.Now().UTC().Add(-2 * time.Hour),
			Files: []models.FileDiff{
				{
					Path: "README.md",
				},
			},
		},
	}

	blameSHAs := map[string]bool{
		"8f2a1c9": true,
	}

	candidates := CorrelateIncident(event, nil, []*models.ParsedStackTrace{st}, commits, nil, blameSHAs)
	if len(candidates) < 1 {
		t.Fatalf("expected at least 1 candidate, got %d", len(candidates))
	}

	top := candidates[0]
	if top.Commit.ShortSHA != "8f2a1c9" {
		t.Errorf("expected top commit to be 8f2a1c9, got %s", top.Commit.ShortSHA)
	}
	if top.Score < 80.0 {
		t.Errorf("expected score >= 80.0, got %f", top.Score)
	}
}

func TestDeterministicBrief(t *testing.T) {
	event := models.IncidentEvent{
		Service:     "checkout",
		Title:       "High 5xx error rate",
		Description: "Panic nil pointer",
		Severity:    models.SeverityCritical,
	}

	st := &models.ParsedStackTrace{
		ErrorType:    "panic",
		ErrorMessage: "nil pointer dereference",
		Frames: []models.StackFrame{
			{File: "pkg/checkout/checkout.go", Line: 114, Function: "Charge"},
		},
	}

	cand := models.CorrelationCandidate{
		Commit: models.CommitInfo{
			SHA:      "8f2a1c9999",
			ShortSHA: "8f2a1c9",
			Author:   "Alice",
			Message:  "refactor checkout logic",
		},
		Score:   95.0,
		Reasons: []string{"File exact match", "Hunk line match"},
	}

	deps := []models.DeploymentInfo{
		{Version: "v2.4.2", CommitSHA: "8f2a1c9999"},
		{Version: "v2.4.1", CommitSHA: "1111111111"},
	}

	runbooks := []models.RunbookMatch{
		{
			ID:    "oom-killed",
			Title: "Container OOMKilled",
			Steps: []string{"Step 1", "Step 2"},
		},
	}

	brief := DeterministicBrief(
		"inc-test-1",
		event,
		nil,
		[]*models.ParsedStackTrace{st},
		[]models.CorrelationCandidate{cand},
		deps,
		142,
		0,
		runbooks,
	)

	if brief == nil {
		t.Fatal("expected non-nil brief")
	}
	if brief.TopCandidate == nil || brief.TopCandidate.Commit.ShortSHA != "8f2a1c9" {
		t.Errorf("expected suspect commit 8f2a1c9, got %+v", brief.TopCandidate)
	}
	if brief.RollbackTarget != "v2.4.1" {
		t.Errorf("expected rollback target v2.4.1, got %q", brief.RollbackTarget)
	}
	if !strings.Contains(brief.ProbableCause, "8f2a1c9") {
		t.Errorf("expected root cause to mention commit SHA, got: %s", brief.ProbableCause)
	}
	if len(brief.MatchedRunbooks) != 1 {
		t.Errorf("expected 1 runbook match, got %d", len(brief.MatchedRunbooks))
	}
}
