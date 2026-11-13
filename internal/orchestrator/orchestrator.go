package orchestrator

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/collectors"
	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/correlator"
	"github.com/alexandrmotologa/incidentpilot/internal/integrations"
	"github.com/alexandrmotologa/incidentpilot/internal/rollback"
	"github.com/alexandrmotologa/incidentpilot/internal/runbooks"
	"github.com/alexandrmotologa/incidentpilot/internal/slack"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	"github.com/google/uuid"
)

type EventBroadcast struct {
	Event      string `json:"event"`
	IncidentID string `json:"incident_id"`
}

type Orchestrator struct {
	cfg             *config.Config
	store           *storage.Store
	logCollector    collectors.LogCollector
	gitProvider     collectors.GitProvider
	slackClient     *slack.Client
	rollbackExec    *rollback.Executor
	promColl        *collectors.PrometheusCollector
	twoWay          *integrations.TwoWayClient
	syncHealthCheck bool

	subscribers map[chan EventBroadcast]bool
	subMu       sync.RWMutex
}

func (o *Orchestrator) SetSyncHealthCheck(sync bool) {
	o.syncHealthCheck = sync
}

func (o *Orchestrator) SetTwoWayClient(tw *integrations.TwoWayClient) {
	o.twoWay = tw
}

func (o *Orchestrator) GetSlackClient() *slack.Client {
	return o.slackClient
}

func NewOrchestrator(
	cfg *config.Config,
	store *storage.Store,
	logColl collectors.LogCollector,
	gitProv collectors.GitProvider,
	slackCli *slack.Client,
	rbExec *rollback.Executor,
) *Orchestrator {
	if logColl == nil {
		logColl = &collectors.JsonlLogCollector{FilePath: "./data/service.log.jsonl"}
	}
	if gitProv == nil {
		gitProv = collectors.BuildGitProvider("", ".", "")
	}
	if slackCli == nil {
		slackCli = &slack.Client{
			WebhookURL: cfg.Notifications.Slack.WebhookURL,
			BotToken:   cfg.Notifications.Slack.BotToken,
			Channel:    cfg.Notifications.Slack.Channel,
		}
	}
	if rbExec == nil {
		rbExec = &rollback.Executor{
			Provider:      "local_git",
			LocalRepoPath: ".",
		}
	}

	return &Orchestrator{
		cfg:          cfg,
		store:        store,
		logCollector: logColl,
		gitProvider:  gitProv,
		slackClient:  slackCli,
		rollbackExec: rbExec,
		promColl:     &collectors.PrometheusCollector{},
		twoWay:       integrations.NewTwoWayClient(),
		subscribers:  make(map[chan EventBroadcast]bool),
	}
}

func (o *Orchestrator) SubscribeEvents() chan EventBroadcast {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	ch := make(chan EventBroadcast, 100)
	o.subscribers[ch] = true
	return ch
}

func (o *Orchestrator) UnsubscribeEvents(ch chan EventBroadcast) {
	o.subMu.Lock()
	defer o.subMu.Unlock()
	if o.subscribers[ch] {
		delete(o.subscribers, ch)
		close(ch)
	}
}

func (o *Orchestrator) Broadcast(event, incidentID string) {
	o.subMu.RLock()
	defer o.subMu.RUnlock()
	msg := EventBroadcast{Event: event, IncidentID: incidentID}
	for ch := range o.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (o *Orchestrator) IngestEvent(ctx context.Context, event models.IncidentEvent, waitForInvestigation bool) (*models.IncidentRecord, bool, error) {
	if event.IsResolved {
		resolved, err := o.ResolveByFingerprint(ctx, event)
		return resolved, false, err
	}

	existing, err := o.store.FindActiveByFingerprint(ctx, event.Fingerprint, o.cfg.DedupWindowSeconds)
	if err == nil && existing != nil {
		existing.AlertCount++
		existing.Timeline = append(existing.Timeline, models.TimelineStep{
			Timestamp: time.Now().UTC(),
			Stage:     "alert_deduplicated",
			Detail:    fmt.Sprintf("Suppressed duplicate alert from %s (count=%d)", event.Source, existing.AlertCount),
		})
		_ = o.store.SaveIncident(ctx, existing)
		o.Broadcast("incident_updated", existing.ID)
		return existing, true, nil
	}

	incID := fmt.Sprintf("inc-%s", uuid.New().String()[:8])
	record := &models.IncidentRecord{
		ID:         incID,
		Event:      event,
		Status:     models.StatusInvestigating,
		AlertCount: 1,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
		Timeline: []models.TimelineStep{
			{
				Timestamp: time.Now().UTC(),
				Stage:     "webhook_received",
				Detail:    fmt.Sprintf("Received %s alert from %s for %s", event.Severity, event.Source, event.Service),
			},
		},
	}

	if err := o.store.SaveIncident(ctx, record); err != nil {
		return nil, false, err
	}
	o.Broadcast("incident_created", record.ID)

	// Two-Way Sync: Auto-Acknowledge on PagerDuty if configured
	if event.Source == models.SourcePagerDuty && o.cfg.PagerDutyAPIToken != "" && event.ExternalID != "" {
		go func() {
			_ = o.twoWay.PagerDutyAcknowledge(context.Background(), o.cfg.PagerDutyAPIToken, event.ExternalID, "incidentpilot@local")
		}()
	}

	if waitForInvestigation {
		rec, err := o.Investigate(ctx, record.ID)
		return rec, false, err
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), time.Duration(o.cfg.InvestigationTimeoutSec)*time.Second)
		defer cancel()
		_, _ = o.Investigate(bgCtx, record.ID)
	}()

	return record, false, nil
}

func (o *Orchestrator) ResolveByFingerprint(ctx context.Context, event models.IncidentEvent) (*models.IncidentRecord, error) {
	existing, err := o.store.FindActiveByFingerprint(ctx, event.Fingerprint, 86400)
	if err != nil || existing == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	existing.Status = models.StatusResolved
	existing.ResolvedAt = &now
	mttr := math.Round(now.Sub(existing.CreatedAt).Seconds()*10) / 10
	existing.MTTRSeconds = &mttr
	existing.Timeline = append(existing.Timeline, models.TimelineStep{
		Timestamp: now,
		Stage:     "auto_resolved",
		Detail:    fmt.Sprintf("Resolved via %s webhook (MTTR: %.1f s)", event.Source, mttr),
	})

	if err := o.store.SaveIncident(ctx, existing); err != nil {
		return nil, err
	}
	o.Broadcast("incident_updated", existing.ID)
	return existing, nil
}

func (o *Orchestrator) Investigate(ctx context.Context, incidentID string) (*models.IncidentRecord, error) {
	record, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || record == nil {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	start := time.Now()
	ev := record.Event

	// Check per-service routing overrides from incidentpilot.yaml
	svcCfg := o.cfg.GetService(ev.Service)
	gitProv := o.gitProvider
	logColl := o.logCollector
	slackCli := o.slackClient

	if svcCfg != nil {
		if svcCfg.Repo != "" || svcCfg.LocalRepoPath != "" {
			gitProv = collectors.BuildGitProvider(svcCfg.Repo, svcCfg.LocalRepoPath, svcCfg.GitHubToken)
		}
		if svcCfg.Observability.LogFilePath != "" {
			logColl = &collectors.JsonlLogCollector{FilePath: svcCfg.Observability.LogFilePath}
		} else if svcCfg.Observability.LokiURL != "" {
			logColl = &collectors.LokiLogCollector{BaseURL: svcCfg.Observability.LokiURL}
		}
		if svcCfg.SlackChannel != "" {
			slackCli = &slack.Client{
				WebhookURL: o.cfg.Notifications.Slack.WebhookURL,
				BotToken:   o.cfg.Notifications.Slack.BotToken,
				Channel:    svcCfg.SlackChannel,
			}
		}
	}

	sinceLogs := ev.TriggeredAt.Add(-time.Duration(o.cfg.LogWindowMinutes) * time.Minute)
	untilLogs := ev.TriggeredAt.Add(2 * time.Minute)
	baselineSince := sinceLogs.Add(-45 * time.Minute)
	sinceGit := ev.TriggeredAt.Add(-time.Duration(o.cfg.GitLookbackHours) * time.Hour)

	var (
		logs         []models.LogEntry
		baselineLogs []models.LogEntry
		commits      []models.CommitInfo
		deployments  []models.DeploymentInfo
		wg           sync.WaitGroup
	)

	wg.Add(4)
	go func() {
		defer wg.Done()
		l, _ := logColl.FetchErrorLogs(ctx, ev.Service, sinceLogs, untilLogs)
		logs = l
	}()
	go func() {
		defer wg.Done()
		bl, _ := logColl.FetchErrorLogs(ctx, ev.Service, baselineSince, sinceLogs)
		baselineLogs = bl
	}()
	go func() {
		defer wg.Done()
		c, _ := gitProv.FetchRecentCommits(ctx, sinceGit, 25)
		commits = c
	}()
	go func() {
		defer wg.Done()
		d, _ := gitProv.FetchRecentDeployments(ctx, ev.Environment, 10)
		deployments = d
	}()
	wg.Wait()

	collectMs := time.Since(start).Milliseconds()
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp:  time.Now().UTC(),
		Stage:      "evidence_collected",
		Detail:     fmt.Sprintf("Fetched %d error logs (15m), %d baseline logs (prior 45m), %d commits, %d deployments", len(logs), len(baselineLogs), len(commits), len(deployments)),
		DurationMs: collectMs,
	})

	// Parse stack traces
	parseStart := time.Now()
	var stacktraces []*models.ParsedStackTrace
	if ev.StacktraceHint != "" {
		if st := collectors.ParseStackTrace(ev.StacktraceHint); st != nil {
			stacktraces = append(stacktraces, st)
		}
	}
	for _, l := range logs {
		raw := l.Stacktrace
		if raw == "" {
			raw = l.Message
		}
		if st := collectors.ParseStackTrace(raw); st != nil && len(st.Frames) > 0 {
			stacktraces = append(stacktraces, st)
		}
	}
	parseMs := time.Since(parseStart).Milliseconds()
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp:  time.Now().UTC(),
		Stage:      "stacktrace_parsed",
		Detail:     fmt.Sprintf("Extracted %d structured stack trace(s)", len(stacktraces)),
		DurationMs: parseMs,
	})

	// Run git blame on top stack frame crash locations
	blameSHAs := make(map[string]bool)
	for i, st := range stacktraces {
		if i >= 2 {
			break
		}
		for j, f := range st.Frames {
			if j >= 3 {
				break
			}
			if f.Line > 0 {
				if sha, err := gitProv.BlameLine(ctx, f.File, f.Line); err == nil && sha != "" {
					blameSHAs[sha] = true
				}
			}
		}
	}

	// Correlate commits and runbooks
	corrStart := time.Now()
	candidates := correlator.CorrelateIncident(ev, logs, stacktraces, commits, deployments, blameSHAs)
	matchedRunbooks := runbooks.MatchRunbooks(ev, logs, o.cfg.RunbooksPath)
	corrMs := time.Since(corrStart).Milliseconds()

	corrDetail := "No direct commit match found"
	if len(candidates) > 0 {
		corrDetail = fmt.Sprintf("Top suspect: %s (score %.1f%%)", candidates[0].Commit.ShortSHA, candidates[0].Score)
	} else if len(matchedRunbooks) > 0 {
		corrDetail = fmt.Sprintf("Matched runbook: %s", matchedRunbooks[0].Title)
	}
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp:  time.Now().UTC(),
		Stage:      "correlation_completed",
		Detail:     corrDetail,
		DurationMs: corrMs,
	})

	totalMs := time.Since(start).Milliseconds()
	brief := correlator.SynthesizeBrief(
		ctx,
		o.cfg.LLMAPIURL,
		o.cfg.LLMAPIKey,
		o.cfg.LLMModel,
		record.ID,
		ev,
		logs,
		stacktraces,
		candidates,
		deployments,
		totalMs,
		len(baselineLogs),
		matchedRunbooks,
	)
	record.Brief = brief

	// Dispatch Slack Card
	delivered, msgTS, _ := slackCli.SendBrief(ctx, record)
	if msgTS != "" {
		record.SlackMessageTS = msgTS
	}
	record.Status = models.StatusBriefSent

	slackDetail := "Brief ready in War Room dashboard"
	if delivered {
		slackDetail = "Sent interactive Incident Brief to Slack"
	}
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp:  time.Now().UTC(),
		Stage:      "brief_dispatched",
		Detail:     slackDetail,
		DurationMs: time.Since(start).Milliseconds() - totalMs,
	})

	if err := o.store.SaveIncident(ctx, record); err != nil {
		return nil, err
	}
	o.Broadcast("incident_updated", record.ID)

	// Two-Way Sync: Update PagerDuty & Sentry
	if ev.Source == models.SourcePagerDuty && o.cfg.PagerDutyAPIToken != "" && ev.ExternalID != "" {
		go func() {
			note := fmt.Sprintf("IncidentPilot Investigation Brief: %s | Suspect: %s | Rollback: %s",
				brief.ProbableCause, brief.TopCandidate.Commit.ShortSHA, brief.RollbackTarget)
			_ = o.twoWay.PagerDutyAddNote(context.Background(), o.cfg.PagerDutyAPIToken, ev.ExternalID, "incidentpilot@local", note)
		}()
	}
	if ev.Source == models.SourceSentry && o.cfg.SentryAuthToken != "" && ev.ExternalID != "" {
		go func() {
			comment := fmt.Sprintf("IncidentPilot: %s (Recommended Rollback: %s)", brief.ProbableCause, brief.RollbackTarget)
			_ = o.twoWay.SentryAddComment(context.Background(), o.cfg.SentryAuthToken, ev.ExternalID, comment)
		}()
	}

	// Evaluate Autonomous Rollback Guardrails
	o.evaluateAutoRollbackPolicy(ctx, record, brief)

	return record, nil
}

func (o *Orchestrator) TriggerRollback(ctx context.Context, incidentID, targetVersion, requestedBy string) (*models.IncidentRecord, *models.RollbackRecord, error) {
	record, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || record == nil {
		return nil, nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	target := targetVersion
	if target == "" {
		if record.Brief != nil && record.Brief.RollbackTarget != "" {
			target = record.Brief.RollbackTarget
		} else {
			target = "previous-stable"
		}
	}

	record.Status = models.StatusRollbackPending
	_ = o.store.SaveIncident(ctx, record)
	o.Broadcast("incident_updated", record.ID)

	executor := o.rollbackExec
	svcCfg := o.cfg.GetService(record.Event.Service)
	if svcCfg != nil {
		prov := svcCfg.Mitigation.RollbackProvider
		if prov == "" {
			prov = "local_git"
		}
		executor = &rollback.Executor{
			Provider:        prov,
			LocalRepoPath:   svcCfg.LocalRepoPath,
			RollbackCommand: svcCfg.Mitigation.RollbackCommand,
			GitHubRepo:      svcCfg.Repo,
			GitHubToken:     svcCfg.GitHubToken,
			WebhookURL:      svcCfg.Mitigation.RollbackWebhook,
		}
	}

	rb, _ := executor.Execute(ctx, record, target, requestedBy)
	_ = o.store.SaveRollback(ctx, rb)
	record.Rollbacks = append(record.Rollbacks, *rb)

	now := time.Now().UTC()
	if rb.Status == "succeeded" {
		record.Status = models.StatusRolledBack
		record.ResolvedAt = &now
		mttr := math.Round(now.Sub(record.CreatedAt).Seconds()*10) / 10
		record.MTTRSeconds = &mttr
		record.Timeline = append(record.Timeline, models.TimelineStep{
			Timestamp: now,
			Stage:     "rollback_executed",
			Detail:    fmt.Sprintf("Rolled back to %s: %s", target, rb.Output),
		})
		_ = o.store.SaveIncident(ctx, record)
		o.Broadcast("incident_updated", record.ID)

		if o.syncHealthCheck {
			o.verifyHealthPostRollback(ctx, record.ID, record.Event.Service, target)
			if updated, err := o.store.GetIncident(ctx, record.ID); err == nil && updated != nil {
				record = updated
			}
		} else {
			go o.verifyHealthPostRollback(context.Background(), record.ID, record.Event.Service, target)
		}
		return record, rb, nil
	} else {
		record.Status = models.StatusRollbackFailed
		record.Timeline = append(record.Timeline, models.TimelineStep{
			Timestamp: now,
			Stage:     "rollback_executed",
			Detail:    fmt.Sprintf("Rollback to %s failed: %s", target, rb.Error),
		})
		_ = o.store.SaveIncident(ctx, record)
		o.Broadcast("incident_updated", record.ID)
		return record, rb, nil
	}
}

func (o *Orchestrator) evaluateAutoRollbackPolicy(ctx context.Context, record *models.IncidentRecord, brief *models.IncidentBrief) {
	if brief == nil || brief.RollbackTarget == "" {
		return
	}

	svcCfg := o.cfg.GetService(record.Event.Service)
	if svcCfg == nil {
		return
	}

	policy := svcCfg.Mitigation.AutoRollback
	allowed := false

	if svcCfg.Mitigation.AllowAutoRollback {
		allowed = true
	}

	if policy.Enabled {
		allowed = true

		if len(policy.Environments) > 0 {
			envMatched := false
			for _, e := range policy.Environments {
				if strings.EqualFold(e, record.Event.Environment) {
					envMatched = true
					break
				}
			}
			if !envMatched {
				record.Timeline = append(record.Timeline, models.TimelineStep{
					Timestamp: time.Now().UTC(),
					Stage:     "guardrail_check_skipped",
					Detail:    fmt.Sprintf("Auto-rollback skipped: environment '%s' not in policy %v", record.Event.Environment, policy.Environments),
				})
				_ = o.store.SaveIncident(ctx, record)
				return
			}
		}

		if policy.MinConfidence > 0 && brief.Confidence < policy.MinConfidence {
			record.Timeline = append(record.Timeline, models.TimelineStep{
				Timestamp: time.Now().UTC(),
				Stage:     "guardrail_check_skipped",
				Detail:    fmt.Sprintf("Auto-rollback skipped: confidence %.1f%% below required %.1f%%", brief.Confidence, policy.MinConfidence),
			})
			_ = o.store.SaveIncident(ctx, record)
			return
		}

		if policy.MinSpikeRatio > 0 && (brief.ErrorSpikeRatio == nil || *brief.ErrorSpikeRatio < policy.MinSpikeRatio) {
			currentRatio := 0.0
			if brief.ErrorSpikeRatio != nil {
				currentRatio = *brief.ErrorSpikeRatio
			}
			record.Timeline = append(record.Timeline, models.TimelineStep{
				Timestamp: time.Now().UTC(),
				Stage:     "guardrail_check_skipped",
				Detail:    fmt.Sprintf("Auto-rollback skipped: spike ratio %.1fx below required %.1fx", currentRatio, policy.MinSpikeRatio),
			})
			_ = o.store.SaveIncident(ctx, record)
			return
		}
	}

	if allowed {
		record.Timeline = append(record.Timeline, models.TimelineStep{
			Timestamp: time.Now().UTC(),
			Stage:     "auto_rollback_triggered",
			Detail:    fmt.Sprintf("Autonomous rollback guardrails passed. Reverting to %s", brief.RollbackTarget),
		})
		_ = o.store.SaveIncident(ctx, record)
		o.Broadcast("incident_updated", record.ID)

		go func() {
			_, _, _ = o.TriggerRollback(context.Background(), record.ID, brief.RollbackTarget, "autonomous-policy")
		}()
	}
}

func (o *Orchestrator) verifyHealthPostRollback(ctx context.Context, incidentID, service, target string) {
	record, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || record == nil {
		return
	}

	record.Status = models.StatusMitigating
	started := time.Now().UTC()
	record.HealthVerification = &models.HealthVerificationRecord{
		Status:    "in_progress",
		StartedAt: started,
		Detail:    fmt.Sprintf("Verifying health post-rollback for service '%s'...", service),
	}
	_ = o.store.SaveIncident(ctx, record)
	o.Broadcast("incident_updated", record.ID)

	waitSec := o.cfg.HealthCheckDurationSec
	if waitSec <= 0 {
		waitSec = 30
	}
	if o.syncHealthCheck {
		waitSec = 1
	}

	time.Sleep(time.Duration(waitSec) * time.Second)

	now := time.Now().UTC()
	postLogs, _ := o.logCollector.FetchErrorLogs(ctx, service, started, now)
	errCount := len(postLogs)

	recUpdated, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || recUpdated == nil {
		return
	}

	completedAt := time.Now().UTC()
	recUpdated.HealthVerification.CompletedAt = &completedAt
	recUpdated.HealthVerification.FinalErrorRate = float64(errCount)

	if errCount == 0 {
		recUpdated.Status = models.StatusVerifiedHealthy
		recUpdated.HealthVerification.Status = "healthy"
		recUpdated.HealthVerification.Detail = fmt.Sprintf("Health verification passed: 0 error logs detected during post-rollback check (%ds window).", waitSec)
		recUpdated.Timeline = append(recUpdated.Timeline, models.TimelineStep{
			Timestamp: completedAt,
			Stage:     "health_verified",
			Detail:    fmt.Sprintf("Service verified healthy after rollback to %s", target),
		})
		_ = o.slackClient.SendMessage(ctx, fmt.Sprintf(":white_check_mark: *Incident %s Verified Healthy*: Rollback to `%s` cleared error spike.", recUpdated.ID, target))
	} else {
		recUpdated.Status = models.StatusEscalated
		recUpdated.HealthVerification.Status = "unhealthy"
		recUpdated.HealthVerification.Detail = fmt.Sprintf("Health verification failed: %d errors observed after rollback to %s. Escalation required.", errCount, target)
		recUpdated.Timeline = append(recUpdated.Timeline, models.TimelineStep{
			Timestamp: completedAt,
			Stage:     "health_verification_failed",
			Detail:    fmt.Sprintf("Post-rollback errors persist (%d errors). Escalated to secondary on-call.", errCount),
		})
		_ = o.slackClient.SendMessage(ctx, fmt.Sprintf(":rotating_light: *ESCALATION REQUIRED (%s)*: Rollback to `%s` did not clear errors (%d errors in post-mitigation check). Please inspect manually.", recUpdated.ID, target, errCount))
	}

	_ = o.store.SaveIncident(ctx, recUpdated)
	o.Broadcast("incident_updated", recUpdated.ID)
}

func (o *Orchestrator) CreatePostmortemIssue(ctx context.Context, incidentID string) (string, error) {
	record, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || record == nil {
		return "", fmt.Errorf("incident not found: %s", incidentID)
	}

	token := o.cfg.GitHubToken
	repo := o.cfg.GitHubRepo
	svcCfg := o.cfg.GetService(record.Event.Service)
	if svcCfg != nil {
		if svcCfg.GitHubToken != "" {
			token = svcCfg.GitHubToken
		}
		if svcCfg.Repo != "" {
			repo = svcCfg.Repo
		}
	}

	if token == "" || repo == "" {
		return "", fmt.Errorf("github_token and repo not configured for service '%s'", record.Event.Service)
	}

	title := fmt.Sprintf("[Postmortem] %s: %s (%s)", record.Event.Service, record.Event.Title, record.ID)
	body := GeneratePostmortemMarkdown(record)

	issueURL, err := o.twoWay.CreateGitHubPostmortemIssue(ctx, token, repo, title, body)
	if err != nil {
		return "", err
	}

	record.PostmortemURL = issueURL
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp: time.Now().UTC(),
		Stage:     "postmortem_issue_created",
		Detail:    fmt.Sprintf("Exported postmortem to GitHub Issue: %s", issueURL),
	})

	_ = o.store.SaveIncident(ctx, record)
	o.Broadcast("incident_updated", record.ID)
	return issueURL, nil
}

func (o *Orchestrator) DismissIncident(ctx context.Context, incidentID, actor string) (*models.IncidentRecord, error) {
	record, err := o.store.GetIncident(ctx, incidentID)
	if err != nil || record == nil {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	record.Status = models.StatusDismissed
	record.Timeline = append(record.Timeline, models.TimelineStep{
		Timestamp: time.Now().UTC(),
		Stage:     "incident_dismissed",
		Detail:    fmt.Sprintf("Dismissed by %s", actor),
	})

	if err := o.store.SaveIncident(ctx, record); err != nil {
		return nil, err
	}
	o.Broadcast("incident_updated", record.ID)
	return record, nil
}

func GeneratePostmortemMarkdown(record *models.IncidentRecord) string {
	ev := record.Event
	brief := record.Brief

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Postmortem: %s (%s)\n\n", ev.Title, record.ID))
	sb.WriteString(fmt.Sprintf("- Service: `%s` (%s)\n", ev.Service, ev.Environment))
	sb.WriteString(fmt.Sprintf("- Severity: `%s`\n", ev.Severity))
	sb.WriteString(fmt.Sprintf("- Source: `%s`\n", ev.Source))
	sb.WriteString(fmt.Sprintf("- Status: `%s`\n", record.Status))
	sb.WriteString(fmt.Sprintf("- Triggered at: `%s`\n", ev.TriggeredAt.Format(time.RFC3339)))
	if record.MTTRSeconds != nil {
		sb.WriteString(fmt.Sprintf("- MTTR: `%.1f s`\n", *record.MTTRSeconds))
	}
	sb.WriteString(fmt.Sprintf("- Deduplicated alert count: `%d`\n\n", record.AlertCount))

	sb.WriteString("## Root cause summary\n\n")
	if brief != nil {
		sb.WriteString(brief.ProbableCause + "\n\n")
		sb.WriteString("## Recommendation\n\n")
		sb.WriteString(brief.Recommendation + "\n\n")
		if len(brief.Evidence) > 0 {
			sb.WriteString("## Evidence\n\n")
			for _, e := range brief.Evidence {
				sb.WriteString(fmt.Sprintf("- %s\n", e))
			}
			sb.WriteString("\n")
		}
		if brief.TopCandidate != nil {
			c := brief.TopCandidate.Commit
			sb.WriteString("## Suspect commit\n\n")
			sb.WriteString(fmt.Sprintf("- SHA: `%s`\n", c.SHA))
			sb.WriteString(fmt.Sprintf("- Author: %s\n", c.Author))
			sb.WriteString(fmt.Sprintf("- Message: %s\n", c.Message))
			sb.WriteString(fmt.Sprintf("- Timestamp: `%s`\n\n", c.Timestamp.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("Investigation did not complete.\n\n")
	}

	sb.WriteString("## Investigation timeline\n\n")
	for _, step := range record.Timeline {
		sb.WriteString(fmt.Sprintf("- `%s` [%s] %s (%d ms)\n", step.Timestamp.Format(time.RFC3339), step.Stage, step.Detail, step.DurationMs))
	}

	if len(record.Rollbacks) > 0 {
		sb.WriteString("\n## Rollback history\n\n")
		for _, rb := range record.Rollbacks {
			detail := rb.Output
			if rb.Status != "succeeded" {
				detail = rb.Error
			}
			sb.WriteString(fmt.Sprintf("- `%s` target=`%s` status=`%s` by `%s`: %s\n", rb.ExecutedAt.Format(time.RFC3339), rb.TargetVersion, rb.Status, rb.RequestedBy, detail))
		}
	}

	return sb.String()
}

func (o *Orchestrator) HandleSlackCommand(ctx context.Context, commandText, channel, threadTS string) string {
	cmd := strings.ToLower(strings.TrimSpace(commandText))

	var record *models.IncidentRecord
	incidents, err := o.store.ListIncidents(ctx, 10, "", "", "")
	if err == nil && len(incidents) > 0 {
		if threadTS != "" {
			for _, inc := range incidents {
				if inc.SlackMessageTS == threadTS {
					record = &inc
					break
				}
			}
		}
		if record == nil {
			record = &incidents[0]
		}
	}

	if record == nil {
		return "No incident records found."
	}

	switch {
	case strings.Contains(cmd, "diff"):
		if record.Brief != nil && record.Brief.TopCandidate != nil {
			c := record.Brief.TopCandidate.Commit
			var patches []string
			for _, f := range c.Files {
				if f.Patch != "" {
					patches = append(patches, fmt.Sprintf("```\n--- %s\n%s\n```", f.Path, f.Patch))
				}
			}
			if len(patches) > 0 {
				return fmt.Sprintf("*Diff for commit `%s` by %s:*\n%s", c.ShortSHA, c.Author, strings.Join(patches, "\n"))
			}
			return fmt.Sprintf("Commit `%s` modified %d file(s) without patch diff cached.", c.ShortSHA, len(c.Files))
		}
		return "No correlated commit diff available for this incident."

	case strings.Contains(cmd, "logs"):
		if record.Brief != nil && len(record.Brief.Evidence) > 0 {
			return fmt.Sprintf("*Evidence Logs for Incident `%s`:*\n• %s", record.ID, strings.Join(record.Brief.Evidence, "\n• "))
		}
		return fmt.Sprintf("No logs captured for incident `%s`.", record.ID)

	case strings.Contains(cmd, "status"):
		mttr := "N/A"
		if record.MTTRSeconds != nil {
			mttr = fmt.Sprintf("%.1fs", *record.MTTRSeconds)
		}
		health := "N/A"
		if record.HealthVerification != nil {
			health = record.HealthVerification.Status
		}
		return fmt.Sprintf("*Status for Incident `%s`:*\n• Status: `%s`\n• MTTR: %s\n• Health Verification: `%s`\n• Rollback Target: `%s`",
			record.ID, record.Status, mttr, health, func() string {
				if record.Brief != nil {
					return record.Brief.RollbackTarget
				}
				return "N/A"
			}())

	case strings.Contains(cmd, "postmortem"):
		if record.PostmortemURL != "" {
			return fmt.Sprintf("*Postmortem Issue:* %s", record.PostmortemURL)
		}
		return fmt.Sprintf("Postmortem available at: `/api/incidents/%s/postmortem.md`", record.ID)

	default:
		return "IncidentPilot Assistant commands:\n• *diff* - View offending commit code diff\n• *logs* - View primary error logs and stacktrace\n• *status* - View incident status, MTTR, and health verification\n• *postmortem* - View postmortem export link"
	}
}
