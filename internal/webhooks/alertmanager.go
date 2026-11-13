package webhooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type alertmanagerPayload struct {
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	Alerts            []struct {
		Status       string            `json:"status"`
		Fingerprint  string            `json:"fingerprint"`
		Labels       map[string]string `json:"labels"`
		Annotations  map[string]string `json:"annotations"`
		StartsAt     string            `json:"startsAt"`
		GeneratorURL string            `json:"generatorURL"`
	} `json:"alerts"`
}

func mapAlertmanagerSeverity(val string) models.Severity {
	switch strings.ToLower(val) {
	case "critical", "page", "fatal", "p1":
		return models.SeverityCritical
	case "warning", "warn", "medium":
		return models.SeverityMedium
	case "info", "low":
		return models.SeverityLow
	default:
		return models.SeverityHigh
	}
}

func ParseAlertmanagerWebhook(body []byte) ([]models.IncidentEvent, error) {
	var payload alertmanagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	var events []models.IncidentEvent
	for i, alert := range payload.Alerts {
		labels := make(map[string]string)
		for k, v := range payload.CommonLabels {
			labels[k] = v
		}
		for k, v := range alert.Labels {
			labels[k] = v
		}

		annotations := make(map[string]string)
		for k, v := range payload.CommonAnnotations {
			annotations[k] = v
		}
		for k, v := range alert.Annotations {
			annotations[k] = v
		}

		service := labels["service"]
		if service == "" {
			service = labels["app"]
		}
		if service == "" {
			service = labels["job"]
		}
		if service == "" {
			service = labels["container"]
		}
		if service == "" {
			service = "unknown-service"
		}

		alertname := labels["alertname"]
		if alertname == "" {
			alertname = "AlertmanagerAlert"
		}

		title := annotations["summary"]
		if title == "" {
			title = fmt.Sprintf("%s on %s", alertname, service)
		}

		desc := annotations["description"]
		if desc == "" {
			desc = title
		}

		fp := alert.Fingerprint
		if fp == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("am:%s:%s", service, alertname)))
			fp = hex.EncodeToString(h[:8])
		}

		env := labels["env"]
		if env == "" {
			env = labels["environment"]
		}
		if env == "" {
			env = "production"
		}

		isResolved := strings.ToLower(alert.Status) == "resolved"

		events = append(events, models.IncidentEvent{
			Source:      models.SourceAlertmanager,
			ExternalID:  fmt.Sprintf("%s-%d", fp, i),
			Fingerprint: fp,
			Service:     service,
			Environment: env,
			Title:       title,
			Description: desc,
			Severity:    mapAlertmanagerSeverity(labels["severity"]),
			TriggeredAt: parseTime(alert.StartsAt),
			Labels:      labels,
			IsResolved:  isResolved,
		})
	}

	return events, nil
}
