package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/benchmark"
	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/orchestrator"
	"github.com/alexandrmotologa/incidentpilot/internal/server"
	"github.com/alexandrmotologa/incidentpilot/internal/simulator"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/internal/tui"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	case "serve":
		cmdServe(os.Args[2:])
	case "replay":
		cmdReplay(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "simulate":
		cmdSimulate(os.Args[2:])
	case "bench":
		cmdBench(os.Args[2:])
	case "top":
		cmdTop(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("IncidentPilot: Autonomous On-Call Incident Responder & Log/Trace Correlator")
	fmt.Println("\nUsage:")
	fmt.Println("  incidentpilot serve [--config ./incidentpilot.yaml] [--port 8080]")
	fmt.Println("  incidentpilot replay --incident-id <id> [--time <RFC3339>]")
	fmt.Println("  incidentpilot list [--status active|all]")
	fmt.Println("  incidentpilot simulate [--scenario go_nil_pointer|python_checkout_error|oom_runbook]")
	fmt.Println("  incidentpilot bench [--config ./incidentpilot.yaml]")
	fmt.Println("  incidentpilot top [--config ./incidentpilot.yaml] [--once]")
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml configuration")
	port := fs.Int("port", 0, "HTTP server port (overrides config)")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if *port > 0 {
		cfg.Port = *port
	}

	store, err := storage.NewStore(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	orch := orchestrator.NewOrchestrator(cfg, store, nil, nil, nil, nil)
	srv := server.NewServer(cfg, store, orch)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	fmt.Printf("[IncidentPilot] Starting autonomous SRE daemon on %s...\n", addr)
	fmt.Printf("[IncidentPilot] War Room Studio available at http://localhost:%d\n", cfg.Port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func cmdReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	incidentID := fs.String("incident-id", "", "ID of the incident to replay")
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml")
	timeStr := fs.String("time", "", "Historical timestamp to replay from (RFC3339)")
	_ = fs.Parse(args)

	if *incidentID == "" {
		fmt.Println("Error: --incident-id is required")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	store, err := storage.NewStore(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx := context.Background()
	rec, err := store.GetIncident(ctx, *incidentID)
	if err != nil || rec == nil {
		fmt.Fprintf(os.Stderr, "Incident not found: %s\n", *incidentID)
		os.Exit(1)
	}

	if *timeStr != "" {
		if t, err := time.Parse(time.RFC3339, *timeStr); err == nil {
			rec.Event.TriggeredAt = t
		}
	}

	orch := orchestrator.NewOrchestrator(cfg, store, nil, nil, nil, nil)
	fmt.Printf("[Replay] Replaying investigation for %s (%s)...\n", rec.ID, rec.Event.Title)
	updated, err := orch.Investigate(ctx, rec.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Replay failed: %v\n", err)
		os.Exit(1)
	}

	if updated.Brief != nil {
		fmt.Printf("Probable Cause: %s\n", updated.Brief.ProbableCause)
		fmt.Printf("Recommendation: %s\n", updated.Brief.Recommendation)
		fmt.Printf("Confidence:     %.1f%%\n", updated.Brief.Confidence)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	status := fs.String("status", "all", "Filter status: active, resolved, or all")
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml")
	_ = fs.Parse(args)

	cfg, _ := config.LoadConfig(*configPath)
	store, err := storage.NewStore(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx := context.Background()
	filterStatus := ""
	if *status == "active" {
		filterStatus = string(models.StatusBriefSent)
	} else if *status == "resolved" {
		filterStatus = string(models.StatusResolved)
	}

	records, err := store.ListIncidents(ctx, 50, "", "", filterStatus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list incidents: %v\n", err)
		os.Exit(1)
	}

	if len(records) == 0 {
		fmt.Println("No incidents found.")
		return
	}

	fmt.Printf("%-14s %-12s %-10s %-20s %-30s\n", "INCIDENT ID", "STATUS", "SEVERITY", "SERVICE", "TITLE")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range records {
		title := r.Event.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}
		fmt.Printf("%-14s %-12s %-10s %-20s %-30s\n", r.ID, r.Status, r.Event.Severity, r.Event.Service, title)
	}
}

func cmdSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	scenario := fs.String("scenario", "go_nil_pointer", "Simulation scenario (go_nil_pointer, python_checkout_error, oom_runbook)")
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml")
	_ = fs.Parse(args)

	cfg, _ := config.LoadConfig(*configPath)
	cfg.DatabasePath = ":memory:" // standalone simulation in memory

	store, err := storage.NewStore(":memory:")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Storage error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	fmt.Printf("[Simulation] Starting scenario '%s'...\n", *scenario)
	start := time.Now()
	rec, simOrch, err := simulator.RunScenarioSimulation(context.Background(), store, cfg, *scenario, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Simulation error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Incident ID:    %s\n", rec.ID)
	if rec.Brief != nil {
		fmt.Printf("Probable Cause: %s\n", rec.Brief.ProbableCause)
		fmt.Printf("Recommendation: %s\n", rec.Brief.Recommendation)
		fmt.Printf("Confidence:     %.1f%%\n", rec.Brief.Confidence)
		fmt.Printf("Duration:       %d ms\n", rec.Brief.InvestigationDurationMs)

		if rec.Brief.TopCandidate != nil {
			fmt.Printf("Suspect SHA:    %s by %s\n", rec.Brief.TopCandidate.Commit.ShortSHA, rec.Brief.TopCandidate.Commit.Author)
		}

		// Execute verified rollback
		updated, rb, _ := simOrch.TriggerRollback(context.Background(), rec.ID, rec.Brief.RollbackTarget, "cli-simulator")
		if rb != nil {
			if rb.Status == "succeeded" {
				fmt.Printf("Rollback:       %s -> %s\n", rb.Status, rb.Output)
			} else {
				fmt.Printf("Rollback:       %s -> error: %s\n", rb.Status, rb.Error)
			}
		}
		fmt.Printf("Final Status:   %s (Total elapsed: %v)\n", updated.Status, time.Since(start).Round(time.Millisecond))
	}
}

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml configuration")
	_ = fs.Parse(args)

	cfg, _ := config.LoadConfig(*configPath)
	tmpDir, err := os.MkdirTemp("", "incidentpilot-bench-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.NewStore(filepath.Join(tmpDir, "bench.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create benchmark store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	fmt.Println("[Benchmark] Running automated SRE correlation & mitigation benchmark suite...")
	report, err := benchmark.RunBenchmarkSuite(context.Background(), cfg, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Benchmark suite execution error: %v\n", err)
		os.Exit(1)
	}

	benchmark.PrintBenchmarkReport(report)
	if report.PassedCount < report.TotalScenarios {
		os.Exit(1)
	}
}

func cmdTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	configPath := fs.String("config", "./incidentpilot.yaml", "Path to incidentpilot.yaml configuration")
	once := fs.Bool("once", false, "Render a single snapshot and exit")
	_ = fs.Parse(args)

	cfg, _ := config.LoadConfig(*configPath)
	store, err := storage.NewStore(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open storage at %s: %v\n", cfg.DatabasePath, err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tui.RunTop(ctx, store, cfg.DatabasePath, *once); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
