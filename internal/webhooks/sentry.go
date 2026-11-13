package webhooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type sentryPayload struct {
	ID          string `json:"id"`
	ProjectName string `json:"project_name"`
	ProjectSlug string `json:"project_slug"`
	Message     string `json:"message"`
	Data        struct {
		Event struct {
			EventID     string `json:"event_id"`
			Project     string `json:"project"`
			Title       string `json:"title"`
			Culprit     string `json:"culprit"`
			Level       string `json:"level"`
			Environment string `json:"environment"`
			Datetime    string `json:"datetime"`
			Timestamp   any    `json:"timestamp"`
			Tags        [][]string `json:"tags"`
			Exception   struct {
				Values []struct {
					Type       string `json:"type"`
					Value      string `json:"value"`
					Stacktrace struct {
						Frames []struct {
							Filename string `json:"filename"`
							AbsPath  string `json:"abs_path"`
							Lineno   int    `json:"lineno"`
							Function string `json:"function"`
						} `json:"frames"`
					} `json:"stacktrace"`
				} `json:"values"`
			} `json:"exception"`
		} `json:"event"`
		Issue struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Culprit string `json:"culprit"`
			Level   string `json:"level"`
			Project struct {
				Slug string `json:"slug"`
			} `json:"project"`
		} `json:"issue"`
	} `json:"data"`
}

func formatSentryFrames(ev sentryPayload) string {
	var lines []string
	for _, val := range ev.Data.Event.Exception.Values {
		lines = append(lines, fmt.Sprintf("%s: %s", val.Type, val.Value))
		for _, frame := range val.Stacktrace.Frames {
			file := frame.Filename
			if file == "" {
				file = frame.AbsPath
			}
			if file == "" {
				file = "unknown"
			}
			fn := frame.Function
			if fn == "" {
				fn = "<frame>"
			}
			lines = append(lines, fmt.Sprintf("  at %s (%s:%d)", fn, file, frame.Lineno))
		}
	}
	return strings.Join(lines, "\n")
}

func mapSentrySeverity(level string) models.Severity {
	switch strings.ToLower(level) {
	case "fatal":
		return models.SeverityCritical
	case "error":
		return models.SeverityHigh
	case "warning":
		return models.SeverityMedium
	case "info", "debug":
		return models.SeverityLow
	default:
		return models.SeverityHigh
	}
}

func ParseSentryWebhook(body []byte) ([]models.IncidentEvent, error) {
	var payload sentryPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	evData := payload.Data.Event
	issueData := payload.Data.Issue

	service := payload.ProjectSlug
	if service == "" {
		service = payload.ProjectName
	}
	if service == "" {
		service = evData.Project
	}
	if service == "" {
		service = issueData.Project.Slug
	}
	if service == "" {
		service = "unknown-service"
	}

	title := evData.Title
	if title == "" {
		title = issueData.Title
	}
	if title == "" {
		title = payload.Message
	}
	if title == "" {
		title = "Sentry Error"
	}

	culprit := evData.Culprit
	if culprit == "" {
		culprit = issueData.Culprit
	}

	desc := culprit
	if desc == "" {
		desc = title
	}

	extID := evData.EventID
	if extID == "" {
		extID = issueData.ID
	}
	if extID == "" {
		extID = payload.ID
	}

	rawFP := fmt.Sprintf("sentry:%s:%s:%s", service, title, culprit)
	h := sha256.Sum256([]byte(rawFP))
	fp := hex.EncodeToString(h[:8])

	sev := mapSentrySeverity(evData.Level)
	if evData.Level == "" {
		sev = mapSentrySeverity(issueData.Level)
	}

	env := evData.Environment
	if env == "" {
		env = "production"
	}

	stackHint := formatSentryFrames(payload)

	labels := make(map[string]string)
	for _, tag := range evData.Tags {
		if len(tag) == 2 {
			labels[tag[0]] = tag[1]
		}
	}

	event := models.IncidentEvent{
		Source:         models.SourceSentry,
		ExternalID:     extID,
		Fingerprint:    fp,
		Service:        service,
		Environment:    env,
		Title:          title,
		Description:    desc,
		Severity:       sev,
		TriggeredAt:    parseTime(evData.Datetime),
		StacktraceHint: stackHint,
		Labels:         labels,
	}

	return []models.IncidentEvent{event}, nil
}
