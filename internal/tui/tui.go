package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func formatAge(t time.Time) string {
	diff := time.Since(t)
	if diff < time.Minute {
		return fmt.Sprintf("%ds ago", int(diff.Seconds()))
	}
	if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	return fmt.Sprintf("%dh ago", int(diff.Hours()))
}

func RenderTopSnapshot(ctx context.Context, store *storage.Store, dbPath string) error {
	metrics, err := store.ComputeMetrics(ctx)
	if err != nil {
		return err
	}

	records, err := store.ListIncidents(ctx, 15, "", "", "")
	if err != nil {
		return err
	}

	var sb strings.Builder
	// Clear screen & home cursor
	sb.WriteString("\033[H\033[2J")

	// Header
	sb.WriteString("\033[1;36m================================================================================\033[0m\n")
	sb.WriteString("\033[1m  IncidentPilot [TOP] — Autonomous On-Call Incident Responder Cockpit\033[0m\n")
	sb.WriteString(fmt.Sprintf("  Database: %s | Time: %s\n", dbPath, time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("\033[1;36m--------------------------------------------------------------------------------\033[0m\n")

	// SRE Metrics Bar
	avgMTTR := "0.0s"
	if metrics.AvgMTTRSeconds != nil {
		avgMTTR = fmt.Sprintf("%.1fs", *metrics.AvgMTTRSeconds)
	}
	sb.WriteString(fmt.Sprintf("  \033[1mTotal:\033[0m %d  |  \033[1;33mActive:\033[0m %d  |  \033[1;32mResolved/Healthy:\033[0m %d  |  \033[1mMTTR:\033[0m %s  |  \033[1;35mHit Rate:\033[0m %.1f%%\n",
		metrics.TotalIncidents, metrics.ActiveIncidents, metrics.ResolvedIncidents, avgMTTR, metrics.CorrelationHitRate))
	sb.WriteString("\033[1;36m================================================================================\033[0m\n")

	// Table Header
	sb.WriteString(fmt.Sprintf("  %-14s %-16s %-10s %-18s %-9s %s\n",
		"INCIDENT ID", "SERVICE", "SEVERITY", "STATUS", "AGE", "TARGET / SUSPECT"))
	sb.WriteString("  " + strings.Repeat("-", 76) + "\n")

	if len(records) == 0 {
		sb.WriteString("  No incidents recorded. System operational and idle.\n")
	} else {
		for _, rec := range records {
			statusColor := "\033[0m"
			switch rec.Status {
			case models.StatusVerifiedHealthy, models.StatusResolved:
				statusColor = "\033[1;32m" // Green
			case models.StatusRolledBack:
				statusColor = "\033[1;34m" // Blue
			case models.StatusEscalated, models.StatusRollbackFailed:
				statusColor = "\033[1;31m" // Red
			case models.StatusInvestigating, models.StatusBriefSent, models.StatusMitigating:
				statusColor = "\033[1;33m" // Yellow
			}

			targetOrSuspect := "-"
			if rec.Brief != nil {
				if rec.Brief.RollbackTarget != "" {
					targetOrSuspect = "revert: " + rec.Brief.RollbackTarget
				} else if rec.Brief.TopCandidate != nil {
					targetOrSuspect = "commit: " + rec.Brief.TopCandidate.Commit.ShortSHA
				} else if len(rec.Brief.MatchedRunbooks) > 0 {
					targetOrSuspect = "runbook: " + rec.Brief.MatchedRunbooks[0].ID
				}
			}

			sb.WriteString(fmt.Sprintf("  %-14s %-16s %-10s %s%-18s\033[0m %-9s %s\n",
				rec.ID,
				rec.Event.Service,
				strings.ToUpper(string(rec.Event.Severity)),
				statusColor,
				rec.Status,
				formatAge(rec.CreatedAt),
				targetOrSuspect,
			))
		}
	}

	sb.WriteString("\033[1;36m--------------------------------------------------------------------------------\033[0m\n")
	sb.WriteString("  Commands: [incidentpilot serve] to launch Studio | [Ctrl+C] to exit\n")
	sb.WriteString("\033[1;36m================================================================================\033[0m\n")

	fmt.Print(sb.String())
	return nil
}

func RunTop(ctx context.Context, store *storage.Store, dbPath string, once bool) error {
	if once {
		return RenderTopSnapshot(ctx, store, dbPath)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Initial render
	if err := RenderTopSnapshot(ctx, store, dbPath); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := RenderTopSnapshot(ctx, store, dbPath); err != nil {
				return err
			}
		}
	}
}
