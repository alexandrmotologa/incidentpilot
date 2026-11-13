package correlator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func computeSpikeRatio(current15m, baseline45m int) *float64 {
	if current15m == 0 && baseline45m == 0 {
		return nil
	}
	baselinePer15m := float64(baseline45m) / 3.0
	if baselinePer15m <= 0 {
		if current15m > 0 {
			val := float64(current15m)
			return &val
		}
		return nil
	}
	val := math.Round((float64(current15m)/baselinePer15m)*100) / 100
	return &val
}

func DeterministicBrief(
	incidentID string,
	event models.IncidentEvent,
	logs []models.LogEntry,
	stacktraces []*models.ParsedStackTrace,
	candidates []models.CorrelationCandidate,
	deployments []models.DeploymentInfo,
	durationMs int64,
	baselineCount45m int,
	runbooks []models.RunbookMatch,
) *models.IncidentBrief {
	var topST *models.ParsedStackTrace
	for _, st := range stacktraces {
		if len(st.Frames) > 0 {
			topST = st
			break
		}
	}
	if topST == nil && len(stacktraces) > 0 {
		topST = stacktraces[0]
	}

	var topCand *models.CorrelationCandidate
	if len(candidates) > 0 {
		topCand = &candidates[0]
	}

	spikeRatio := computeSpikeRatio(len(logs), baselineCount45m)
	spikeNote := ""
	if spikeRatio != nil && baselineCount45m == 0 && len(logs) > 0 {
		spikeNote = fmt.Sprintf(" (new regression: 0 errors in prior 45m -> %d in last 15m)", len(logs))
	} else if spikeRatio != nil {
		spikeNote = fmt.Sprintf(" (%.1fx vs prior 45m baseline of %d)", *spikeRatio, baselineCount45m)
	}

	var evidence []string
	evidence = append(evidence, fmt.Sprintf("Collected %d error log(s) for service '%s' in the last 15 minutes%s.", len(logs), event.Service, spikeNote))

	if topST != nil && len(topST.Frames) > 0 {
		f0 := topST.Frames[0]
		loc := f0.File
		if f0.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f0.File, f0.Line)
		}
		desc := topST.ErrorType
		if topST.ErrorMessage != "" {
			desc += ": " + topST.ErrorMessage
		}
		evidence = append(evidence, fmt.Sprintf("Primary stack frame: %s (%s).", loc, desc))
	}

	var probableCause string
	var recommendation string
	var rollbackTarget string
	var confidence float64

	if topCand != nil {
		evidence = append(evidence, topCand.Reasons...)
		c := topCand.Commit
		rollbackTarget = topCand.RollbackTarget
		if rollbackTarget == "" {
			rollbackTarget = SelectRollbackTarget(deployments, &c)
		}
		if rollbackTarget == "" {
			rollbackTarget = "previous-stable"
		}

		locationStr := ""
		if len(topCand.MatchedLines) > 0 {
			locationStr = topCand.MatchedLines[0]
		} else if len(topCand.MatchedFiles) > 0 {
			locationStr = filepath.Base(topCand.MatchedFiles[0])
		} else if topST != nil && len(topST.Frames) > 0 {
			f0 := topST.Frames[0]
			if f0.Line > 0 {
				locationStr = fmt.Sprintf("%s:%d", filepath.Base(f0.File), f0.Line)
			} else {
				locationStr = filepath.Base(f0.File)
			}
		}

		errSummary := event.Title
		if topST != nil && topST.ErrorMessage != "" {
			errSummary = topST.ErrorMessage
		}

		locClause := ""
		if locationStr != "" {
			locClause = fmt.Sprintf(" in %s", locationStr)
		}

		probableCause = fmt.Sprintf("Commit %s by %s ('%s') correlates with %s%s.", c.ShortSHA, c.Author, c.Message, errSummary, locClause)
		recommendation = fmt.Sprintf("Rollback %s to %s", event.Service, rollbackTarget)
		confidence = topCand.Score
	} else if len(runbooks) > 0 {
		rb := runbooks[0]
		if len(deployments) >= 2 {
			rollbackTarget = deployments[1].Version
		} else {
			rollbackTarget = "previous-stable"
		}
		probableCause = fmt.Sprintf("Matched operational runbook '%s' (pattern '%s') across %d error(s) for %s.", rb.Title, rb.MatchedPattern, len(logs), event.Service)
		if len(rb.Steps) > 0 {
			recommendation = rb.Steps[0]
		} else {
			recommendation = fmt.Sprintf("Follow runbook %s", rb.Title)
		}
		confidence = 65.0
	} else {
		if len(deployments) >= 2 {
			rollbackTarget = deployments[1].Version
		} else {
			rollbackTarget = "previous-stable"
		}
		probableCause = fmt.Sprintf("No recent commit directly matched the stack trace; observed %d error(s) for %s: %s.", len(logs), event.Service, event.Title)
		recommendation = fmt.Sprintf("Inspect recent logs and consider rolling back %s to %s", event.Service, rollbackTarget)
		if len(logs) > 0 {
			confidence = 25.0
		} else {
			confidence = 10.0
		}
	}

	summary := fmt.Sprintf("%s Recommendation: %s.", probableCause, recommendation)

	candSlice := candidates
	if len(candSlice) > 3 {
		candSlice = candSlice[:3]
	}

	return &models.IncidentBrief{
		IncidentID:              incidentID,
		Summary:                 summary,
		ProbableCause:           probableCause,
		Recommendation:          recommendation,
		RollbackTarget:          rollbackTarget,
		Confidence:              confidence,
		Evidence:                evidence,
		ErrorCount15m:           len(logs),
		BaselineErrorCount45m:   baselineCount45m,
		ErrorSpikeRatio:         spikeRatio,
		TopStacktrace:           topST,
		TopCandidate:            topCand,
		Candidates:              candSlice,
		MatchedRunbooks:         runbooks,
		InvestigationDurationMs: durationMs,
		SynthesisMode:           "deterministic",
	}
}

func SynthesizeBrief(
	ctx context.Context,
	llmURL, llmKey, llmModel string,
	incidentID string,
	event models.IncidentEvent,
	logs []models.LogEntry,
	stacktraces []*models.ParsedStackTrace,
	candidates []models.CorrelationCandidate,
	deployments []models.DeploymentInfo,
	durationMs int64,
	baselineCount45m int,
	runbooks []models.RunbookMatch,
) *models.IncidentBrief {
	base := DeterministicBrief(
		incidentID,
		event,
		logs,
		stacktraces,
		candidates,
		deployments,
		durationMs,
		baselineCount45m,
		runbooks,
	)

	if llmKey == "" || llmURL == "" {
		return base
	}

	// Optional LLM refinement (OpenAI-compatible endpoint)
	reqBody := map[string]any{
		"model": llmModel,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": fmt.Sprintf("You are an autonomous SRE incident responder. Evidence: %s. Return a JSON object with 'probable_cause', 'recommendation', 'summary'.", base.Summary),
			},
		},
		"response_format": map[string]string{"type": "json_object"},
		"temperature":     0.1,
	}

	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return base
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, llmURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return base
	}
	req.Header.Set("Authorization", "Bearer "+llmKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return base
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var llmResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&llmResp); err == nil && len(llmResp.Choices) > 0 {
			var parsed struct {
				ProbableCause  string `json:"probable_cause"`
				Recommendation string `json:"recommendation"`
				Summary        string `json:"summary"`
			}
			if err := json.Unmarshal([]byte(llmResp.Choices[0].Message.Content), &parsed); err == nil {
				if parsed.ProbableCause != "" {
					base.ProbableCause = parsed.ProbableCause
				}
				if parsed.Recommendation != "" {
					base.Recommendation = parsed.Recommendation
				}
				if parsed.Summary != "" {
					base.Summary = parsed.Summary
				}
				base.SynthesisMode = "llm"
			}
		}
	}

	return base
}
