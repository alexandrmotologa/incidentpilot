package webhooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type datadogPayload struct {
	ID             any    `json:"id"`
	Title          string `json:"title"`
	Body           string `json:"body"`
	AlertType      string `json:"alert_type"`       // "error", "warning", "info", "success"
	Transition     string `json:"alert_transition"` // "Recovered", "Triggered", "Warn"
	Priority       string `json:"priority"`         // "normal", "low"
	Tags           string `json:"tags"`             // comma-separated "service:checkout,env:prod"
	Date           int64  `json:"date"`             // Unix epoch timestamp in ms or s
	LastUpdated    int64  `json:"last_updated"`
	EventClusterID string `json:"event_cluster_id"`
}

func mapDatadogSeverity(alertType string) models.Severity {
	switch strings.ToLower(alertType) {
	case "error":
		return models.SeverityCritical
	case "warning":
		return models.SeverityMedium
	case "info", "success":
		return models.SeverityLow
	default:
		return models.SeverityHigh
	}
}

func ParseDatadogWebhook(body []byte) ([]models.IncidentEvent, error) {
	var payload datadogPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	labels := make(map[string]string)
	service := "unknown-service"
	env := "production"

	for _, tag := range strings.Split(payload.Tags, ",") {
		parts := strings.SplitN(strings.TrimSpace(tag), ":", 2)
		if len(parts) == 2 {
			labels[parts[0]] = parts[1]
			if parts[0] == "service" || parts[0] == "app" {
				service = parts[1]
			} else if parts[0] == "env" || parts[0] == "environment" {
				env = parts[1]
			}
		}
	}

	title := payload.Title
	if title == "" {
		title = "Datadog Alert"
	}

	desc := payload.Body
	if desc == "" {
		desc = title
	}

	extID := fmt.Sprintf("%v", payload.ID)
	if extID == "" || extID == "<nil>" {
		extID = fmt.Sprintf("dd-%d", time.Now().UnixNano())
	}

	rawFP := fmt.Sprintf("datadog:%s:%s", service, title)
	h := sha256.Sum256([]byte(rawFP))
	fp := hex.EncodeToString(h[:8])

	isResolved := strings.EqualFold(payload.Transition, "Recovered") || strings.EqualFold(payload.AlertType, "success")

	t := time.Now().UTC()
	if payload.Date > 0 {
		if payload.Date > 1e12 {
			t = time.UnixMilli(payload.Date).UTC()
		} else {
			t = time.Unix(payload.Date, 0).UTC()
		}
	}

	stackHint := ""
	if strings.Contains(desc, "Traceback") || strings.Contains(desc, "panic:") || strings.Contains(desc, "  at ") {
		stackHint = desc
	}

	event := models.IncidentEvent{
		Source:         models.SourceDatadog,
		ExternalID:     extID,
		Fingerprint:    fp,
		Service:        service,
		Environment:    env,
		Title:          title,
		Description:    desc,
		Severity:       mapDatadogSeverity(payload.AlertType),
		TriggeredAt:    t,
		StacktraceHint: stackHint,
		Labels:         labels,
		IsResolved:     isResolved,
	}

	return []models.IncidentEvent{event}, nil
}
