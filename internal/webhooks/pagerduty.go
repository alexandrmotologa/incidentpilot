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

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return t.UTC()
	}
	t, err = time.Parse(time.RFC3339, raw)
	if err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func mapPDSeverity(urgency, priority string) models.Severity {
	val := strings.ToLower(priority)
	if val == "" {
		val = strings.ToLower(urgency)
	}
	switch val {
	case "p1", "critical", "sev1", "fatal":
		return models.SeverityCritical
	case "p2", "high", "sev2":
		return models.SeverityHigh
	case "p3", "medium", "sev3":
		return models.SeverityMedium
	case "p4", "p5", "low", "sev4":
		return models.SeverityLow
	default:
		return models.SeverityHigh
	}
}

func pdFingerprint(service, title, extID string) string {
	raw := fmt.Sprintf("pagerduty:%s:%s", service, title)
	if title == "" {
		raw = fmt.Sprintf("pagerduty:%s:%s", service, extID)
	}
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:8])
}

type pdV3Payload struct {
	Event struct {
		EventType  string `json:"event_type"`
		ID         string `json:"id"`
		OccurredAt string `json:"occurred_at"`
		Data       struct {
			ID          string `json:"id"`
			Number      int    `json:"number"`
			Title       string `json:"title"`
			Summary     string `json:"summary"`
			Urgency     string `json:"urgency"`
			Environment string `json:"environment"`
			Service     struct {
				Summary string `json:"summary"`
				Name    string `json:"name"`
			} `json:"service"`
			Priority struct {
				Summary string `json:"summary"`
				Name    string `json:"name"`
			} `json:"priority"`
			Body struct {
				Details string `json:"details"`
			} `json:"body"`
		} `json:"data"`
	} `json:"event"`
}

type pdV2Payload struct {
	Messages []struct {
		Event     string `json:"event"`
		ID        string `json:"id"`
		CreatedOn string `json:"created_on"`
		Incident  struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Urgency     string `json:"urgency"`
			Service     struct {
				Name    string `json:"name"`
				Summary string `json:"summary"`
			} `json:"service"`
			Priority struct {
				Name string `json:"name"`
			} `json:"priority"`
		} `json:"incident"`
	} `json:"messages"`
}

func ParsePagerDutyWebhook(body []byte) ([]models.IncidentEvent, error) {
	// Try V3 first
	var v3 pdV3Payload
	if err := json.Unmarshal(body, &v3); err == nil && v3.Event.EventType != "" {
		eventType := v3.Event.EventType
		if eventType != "incident.triggered" && eventType != "incident.escalated" && eventType != "incident.resolved" {
			return nil, nil
		}

		service := v3.Event.Data.Service.Summary
		if service == "" {
			service = v3.Event.Data.Service.Name
		}
		if service == "" {
			service = "unknown-service"
		}

		title := v3.Event.Data.Title
		if title == "" {
			title = v3.Event.Data.Summary
		}
		if title == "" {
			title = "PagerDuty Incident"
		}

		extID := v3.Event.Data.ID
		if extID == "" {
			extID = v3.Event.ID
		}

		desc := v3.Event.Data.Body.Details
		if desc == "" {
			desc = title
		}

		env := v3.Event.Data.Environment
		if env == "" {
			env = "production"
		}

		sev := mapPDSeverity(v3.Event.Data.Urgency, v3.Event.Data.Priority.Summary)
		isResolved := eventType == "incident.resolved"

		stackHint := ""
		if strings.Contains(desc, ".go:") || strings.Contains(desc, ".py") || strings.Contains(desc, "at ") {
			stackHint = desc
		}

		ev := models.IncidentEvent{
			Source:         models.SourcePagerDuty,
			ExternalID:     extID,
			Fingerprint:    pdFingerprint(service, title, extID),
			Service:        service,
			Environment:    env,
			Title:          title,
			Description:    desc,
			Severity:       sev,
			TriggeredAt:    parseTime(v3.Event.OccurredAt),
			StacktraceHint: stackHint,
			Labels: map[string]string{
				"incident_number": fmt.Sprintf("%d", v3.Event.Data.Number),
			},
			IsResolved: isResolved,
		}
		return []models.IncidentEvent{ev}, nil
	}

	// Try V2 format
	var v2 pdV2Payload
	if err := json.Unmarshal(body, &v2); err == nil && len(v2.Messages) > 0 {
		var events []models.IncidentEvent
		for _, msg := range v2.Messages {
			if msg.Event != "incident.trigger" && msg.Event != "incident.escalate" && msg.Event != "incident.resolve" {
				continue
			}

			service := msg.Incident.Service.Name
			if service == "" {
				service = msg.Incident.Service.Summary
			}
			if service == "" {
				service = "unknown-service"
			}

			title := msg.Incident.Title
			if title == "" {
				title = msg.Incident.Summary
			}
			if title == "" {
				title = "PagerDuty Incident"
			}

			desc := msg.Incident.Description
			if desc == "" {
				desc = title
			}

			extID := msg.Incident.ID
			if extID == "" {
				extID = msg.ID
			}

			events = append(events, models.IncidentEvent{
				Source:      models.SourcePagerDuty,
				ExternalID:  extID,
				Fingerprint: pdFingerprint(service, title, extID),
				Service:     service,
				Environment: "production",
				Title:       title,
				Description: desc,
				Severity:    mapPDSeverity(msg.Incident.Urgency, msg.Incident.Priority.Name),
				TriggeredAt: parseTime(msg.CreatedOn),
				IsResolved:  msg.Event == "incident.resolve",
			})
		}
		return events, nil
	}

	return nil, nil
}
