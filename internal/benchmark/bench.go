package benchmark

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/runbooks"
	"github.com/alexandrmotologa/incidentpilot/internal/simulator"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type ScenarioResult struct {
	Name       string
	Expected   string
	Detected   string
	Passed     bool
	DurationMs int64
}

type BenchmarkReport struct {
	TotalScenarios int
	PassedCount    int
	Accuracy       float64
	MeanDurationMs float64
	Results        []ScenarioResult
}

func RunBenchmarkSuite(ctx context.Context, cfg *config.Config, store *storage.Store) (*BenchmarkReport, error) {
	var results []ScenarioResult

	// 1. Go Nil Pointer Scenario
	startGo := time.Now()
	recGo, _, errGo := simulator.RunScenarioSimulation(ctx, store, cfg, "go_nil_pointer", nil)
	durGo := time.Since(startGo).Milliseconds()
	passGo := false
	detectedGo := "none"
	if errGo == nil && recGo != nil && recGo.Brief != nil {
		if recGo.Brief.TopCandidate != nil {
			detectedGo = recGo.Brief.TopCandidate.Commit.ShortSHA
			passGo = recGo.Brief.RollbackTarget == "v2.4.1"
		}
	}
	results = append(results, ScenarioResult{
		Name:       "go_nil_pointer",
		Expected:   "rollback to v2.4.1",
		Detected:   detectedGo,
		Passed:     passGo,
		DurationMs: durGo,
	})

	// 2. Python ZeroDivision Scenario
	startPy := time.Now()
	recPy, _, errPy := simulator.RunScenarioSimulation(ctx, store, cfg, "python_checkout_error", nil)
	durPy := time.Since(startPy).Milliseconds()
	passPy := false
	detectedPy := "none"
	if errPy == nil && recPy != nil && recPy.Brief != nil {
		if recPy.Brief.TopCandidate != nil {
			detectedPy = recPy.Brief.TopCandidate.Commit.ShortSHA
			passPy = recPy.Brief.RollbackTarget == "v1.8.0"
		}
	}
	results = append(results, ScenarioResult{
		Name:       "python_zero_division",
		Expected:   "rollback to v1.8.0",
		Detected:   detectedPy,
		Passed:     passPy,
		DurationMs: durPy,
	})

	// 3. Infrastructure OOMKilled Scenario
	startOOM := time.Now()
	evOOM := models.IncidentEvent{
		Service:     "video-transcoder",
		Title:       "Pod killed by SIGKILL (exit 137)",
		Description: "OOMKilled memory limit exceeded",
	}
	matchesOOM := runbooks.MatchRunbooks(evOOM, nil, cfg.RunbooksPath)
	durOOM := time.Since(startOOM).Milliseconds()
	passOOM := len(matchesOOM) > 0 && matchesOOM[0].ID == "oom-killed"
	detectedOOM := "none"
	if len(matchesOOM) > 0 {
		detectedOOM = matchesOOM[0].ID
	}
	results = append(results, ScenarioResult{
		Name:       "infra_oom_killed",
		Expected:   "oom-killed",
		Detected:   detectedOOM,
		Passed:     passOOM,
		DurationMs: durOOM,
	})

	// 4. Database Connection Pool Exhaustion Scenario
	startDB := time.Now()
	evDB := models.IncidentEvent{
		Service: "payment-gateway",
		Title:   "Service latency degraded",
	}
	logsDB := []models.LogEntry{
		{Message: "failed to acquire connection from pool: timeout waiting for connection slot"},
	}
	matchesDB := runbooks.MatchRunbooks(evDB, logsDB, cfg.RunbooksPath)
	durDB := time.Since(startDB).Milliseconds()
	passDB := len(matchesDB) > 0 && matchesDB[0].ID == "db-pool-exhausted"
	detectedDB := "none"
	if len(matchesDB) > 0 {
		detectedDB = matchesDB[0].ID
	}
	results = append(results, ScenarioResult{
		Name:       "db_pool_exhaustion",
		Expected:   "db-pool-exhausted",
		Detected:   detectedDB,
		Passed:     passDB,
		DurationMs: durDB,
	})

	// 5. Upstream HTTP 429 Rate Limit Scenario
	startRate := time.Now()
	evRate := models.IncidentEvent{
		Service:     "stripe-sync",
		Title:       "HTTP 429 Too Many Requests received from upstream",
		Description: "rate limit exceeded on stripe charges api",
	}
	matchesRate := runbooks.MatchRunbooks(evRate, nil, cfg.RunbooksPath)
	durRate := time.Since(startRate).Milliseconds()
	passRate := len(matchesRate) > 0 && matchesRate[0].ID == "upstream-rate-limit"
	detectedRate := "none"
	if len(matchesRate) > 0 {
		detectedRate = matchesRate[0].ID
	}
	results = append(results, ScenarioResult{
		Name:       "upstream_rate_limit_429",
		Expected:   "upstream-rate-limit",
		Detected:   detectedRate,
		Passed:     passRate,
		DurationMs: durRate,
	})

	// Calculate aggregates
	passed := 0
	var totalDuration int64
	for _, r := range results {
		if r.Passed {
			passed++
		}
		totalDuration += r.DurationMs
	}

	report := &BenchmarkReport{
		TotalScenarios: len(results),
		PassedCount:    passed,
		Accuracy:       float64(passed) / float64(len(results)) * 100.0,
		MeanDurationMs: float64(totalDuration) / float64(len(results)),
		Results:        results,
	}

	return report, nil
}

func PrintBenchmarkReport(report *BenchmarkReport) {
	fmt.Println("IncidentPilot: SRE Correlation & Mitigation Benchmark Suite")
	fmt.Println(strings.Repeat("=", 68))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SCENARIO\tEXPECTED\tDETECTED\tSTATUS\tDURATION")
	for _, r := range report.Results {
		statusStr := "PASS"
		if !r.Passed {
			statusStr = "FAIL"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d ms\n", r.Name, r.Expected, r.Detected, statusStr, r.DurationMs)
	}
	w.Flush()

	fmt.Println(strings.Repeat("-", 68))
	fmt.Printf("Benchmark Summary: %d/%d passed (%.1f%% accuracy) | Mean Latency: %.1f ms\n",
		report.PassedCount, report.TotalScenarios, report.Accuracy, report.MeanDurationMs)
}
