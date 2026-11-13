package simulator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/collectors"
	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/orchestrator"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/internal/webhooks"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	"github.com/google/uuid"
)

func runGit(repoDir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %v failed: %s (%w)", args, string(out), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func RunScenarioSimulation(
	ctx context.Context,
	store *storage.Store,
	baseCfg *config.Config,
	scenario string,
	orch *orchestrator.Orchestrator,
) (*models.IncidentRecord, *orchestrator.Orchestrator, error) {
	simID := uuid.New().String()[:6]
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("incidentpilot-sim-%s", simID))
	repoDir := filepath.Join(baseDir, "repo")
	_ = os.MkdirAll(repoDir, 0755)
	defer func() {
		// Clean up later or keep for debugging
	}()

	_, _ = runGit(repoDir, "init", "-b", "main")
	_, _ = runGit(repoDir, "config", "user.name", "Alexandr Motologa")
	_, _ = runGit(repoDir, "config", "user.email", "alex@example.com")

	now := time.Now().UTC()
	logPath := filepath.Join(baseDir, "service.log.jsonl")

	var event models.IncidentEvent
	var serviceName string

	if scenario == "python_checkout_error" {
		serviceName = fmt.Sprintf("billing-worker-%s", simID)
		targetFile := filepath.Join(repoDir, "app", "billing.py")
		_ = os.MkdirAll(filepath.Dir(targetFile), 0755)

		var lines []string
		for i := 1; i <= 80; i++ {
			lines = append(lines, fmt.Sprintf("# line %d", i))
		}
		lines = append(lines,
			"def calculate_tax(amount: float, count: int) -> float:",
			"    if count <= 0:",
			"        return 0.0",
			"    return amount / count",
		)
		_ = os.WriteFile(targetFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		_, _ = runGit(repoDir, "add", ".")
		_, _ = runGit(repoDir, "commit", "-m", "chore: release v1.8.0")
		_, _ = runGit(repoDir, "tag", "-a", "v1.8.0", "-m", "Release v1.8.0")

		lines[81] = "    # removed zero guard for batch speed"
		lines[82] = "    return amount / count"
		_ = os.WriteFile(targetFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		_, _ = runGit(repoDir, "add", ".")
		_, _ = runGit(repoDir, "commit", "-m", "perf: remove batch count check in billing")
		_, _ = runGit(repoDir, "tag", "-a", "v1.8.1", "-m", "Release v1.8.1")

		stack := "Traceback (most recent call last):\n  File \"/srv/app/billing.py\", line 82, in calculate_tax\n    return amount / count\nZeroDivisionError: division by zero"
		logEntries := []map[string]any{
			{
				"timestamp":  now.Add(-4 * time.Minute).Format(time.RFC3339Nano),
				"level":      "ERROR",
				"service":    serviceName,
				"message":    "ZeroDivisionError: division by zero",
				"stacktrace": stack,
			},
			{
				"timestamp":  now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
				"level":      "FATAL",
				"service":    serviceName,
				"message":    "ZeroDivisionError: division by zero",
				"stacktrace": stack,
			},
		}
		writeJSONLLogs(logPath, logEntries)

		sentryPayload := map[string]any{
			"project_slug": serviceName,
			"data": map[string]any{
				"event": map[string]any{
					"event_id": fmt.Sprintf("sen-%s", simID),
					"title":    "ZeroDivisionError: division by zero",
					"level":    "error",
					"datetime": now.Format(time.RFC3339Nano),
					"exception": map[string]any{
						"values": []map[string]any{
							{
								"type":  "ZeroDivisionError",
								"value": "division by zero",
								"stacktrace": map[string]any{
									"frames": []map[string]any{
										{
											"filename": "/srv/app/billing.py",
											"lineno":   82,
											"function": "calculate_tax",
										},
									},
								},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(sentryPayload)
		evs, _ := webhooks.ParseSentryWebhook(data)
		event = evs[0]

	} else if scenario == "oom_runbook" {
		serviceName = fmt.Sprintf("media-transcoder-%s", simID)
		readme := filepath.Join(repoDir, "README.md")
		_ = os.WriteFile(readme, []byte("media-transcoder\n"), 0644)
		_, _ = runGit(repoDir, "add", ".")
		_, _ = runGit(repoDir, "commit", "-m", "chore: release v3.1.0")
		_, _ = runGit(repoDir, "tag", "-a", "v3.1.0", "-m", "Release v3.1.0")

		logEntries := []map[string]any{
			{
				"timestamp": now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
				"level":     "FATAL",
				"service":   serviceName,
				"message":   "Container terminated with exit code 137 (OOMKilled): memory limit reached",
			},
			{
				"timestamp": now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
				"level":     "ERROR",
				"service":   serviceName,
				"message":   "Out of memory: cannot allocate memory for worker buffer",
			},
		}
		writeJSONLLogs(logPath, logEntries)

		amPayload := map[string]any{
			"alerts": []map[string]any{
				{
					"status":      "firing",
					"fingerprint": fmt.Sprintf("am-%s", simID),
					"labels": map[string]string{
						"service":   serviceName,
						"alertname": "PodOOMKilled",
						"severity":  "critical",
					},
					"annotations": map[string]string{
						"summary":     fmt.Sprintf("%s OOMKilled (exit code 137)", serviceName),
						"description": "Pod exceeded 2Gi memory limit during batch transcode",
					},
					"startsAt": now.Format(time.RFC3339Nano),
				},
			},
		}
		data, _ := json.Marshal(amPayload)
		evs, _ := webhooks.ParseAlertmanagerWebhook(data)
		event = evs[0]

	} else {
		// Default: Go nil pointer (PagerDuty)
		serviceName = fmt.Sprintf("checkout-api-%s", simID)
		checkoutFile := filepath.Join(repoDir, "pkg", "checkout", "checkout.go")
		_ = os.MkdirAll(filepath.Dir(checkoutFile), 0755)

		var lines []string
		for i := 1; i <= 109; i++ {
			lines = append(lines, fmt.Sprintf("// line %d", i))
		}
		lines = append(lines,
			"func Charge(req *ChargeRequest) error {",
			"    if req == nil || req.Customer == nil {",
			"        return errors.New(\"missing customer\")",
			"    }",
			"    return gateway.Submit(req.SafeCustomerID())",
			"}",
		)
		_ = os.WriteFile(checkoutFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		_, _ = runGit(repoDir, "add", ".")
		_, _ = runGit(repoDir, "commit", "-m", "chore: release v2.4.1")
		_, _ = runGit(repoDir, "tag", "-a", "v2.4.1", "-m", "Release v2.4.1")

		lines[110] = "    // removed nil guard for fast-path"
		lines[113] = "    return gateway.Submit(req.Customer.ID)"
		_ = os.WriteFile(checkoutFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		_, _ = runGit(repoDir, "add", ".")
		_, _ = runGit(repoDir, "commit", "-m", "perf: fast-path checkout customer lookup")
		_, _ = runGit(repoDir, "tag", "-a", "v2.4.2", "-m", "Release v2.4.2")

		stack := "panic: runtime error: invalid memory address or nil pointer dereference\ngithub.com/acme/checkout/pkg/checkout.Charge(0x0)\n\t/app/pkg/checkout/checkout.go:114 +0x2c"
		logEntries := []map[string]any{
			{
				"timestamp":  now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
				"level":      "ERROR",
				"service":    serviceName,
				"message":    "panic: runtime error: invalid memory address or nil pointer dereference",
				"stacktrace": stack,
			},
			{
				"timestamp":  now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
				"level":      "FATAL",
				"service":    serviceName,
				"message":    "panic: runtime error: invalid memory address or nil pointer dereference",
				"stacktrace": stack,
			},
		}
		writeJSONLLogs(logPath, logEntries)

		pdPayload := map[string]any{
			"event": map[string]any{
				"event_type":  "incident.triggered",
				"occurred_at": now.Format(time.RFC3339Nano),
				"data": map[string]any{
					"id":      fmt.Sprintf("PD-%s", simID),
					"number":  901,
					"title":   fmt.Sprintf("High 5xx rate on %s", serviceName),
					"urgency": "high",
					"service": map[string]string{"summary": serviceName},
					"body":    map[string]string{"details": "502 Bad Gateway spike after v2.4.2 deploy"},
				},
			},
		}
		data, _ := json.Marshal(pdPayload)
		evs, _ := webhooks.ParsePagerDutyWebhook(data)
		event = evs[0]
	}

	simCfg := *baseCfg
	simCfg.Services = append(simCfg.Services, config.ServiceConfig{
		Name:          serviceName,
		LocalRepoPath: repoDir,
		Observability: config.ObservabilityConfig{
			LogFilePath: logPath,
		},
		Mitigation: config.MitigationConfig{
			RollbackProvider: "local_git",
		},
	})

	simOrch := orchestrator.NewOrchestrator(
		&simCfg,
		store,
		&collectors.JsonlLogCollector{FilePath: logPath},
		&collectors.LocalGitProvider{RepoPath: repoDir},
		nil,
		nil,
	)

	rec, _, err := simOrch.IngestEvent(ctx, event, true)
	if err != nil {
		return nil, nil, err
	}

	if orch != nil {
		orch.Broadcast("incident_created", rec.ID)
	}
	return rec, simOrch, nil
}

func writeJSONLLogs(filePath string, entries []map[string]any) {
	f, _ := os.Create(filePath)
	defer f.Close()
	for _, entry := range entries {
		data, _ := json.Marshal(entry)
		_, _ = f.Write(append(data, '\n'))
	}
}
