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

type genericPayload struct {
	ID          string            `json:"id"`
	ExternalID  string            `json:"external_id"`
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Title       string            `json:"title"`
	Message     string            `json:"message"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Fingerprint string            `json:"fingerprint"`
	Stacktrace  string            `json:"stacktrace"`
	Labels      map[string]string `json:"labels"`
	IsResolved  bool              `json:"is_resolved"`
}

func ParseGenericWebhook(body []byte) ([]models.IncidentEvent, error) {
	var payload genericPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	service := payload.Service
	if service == "" {
		service = "unknown-service"
	}

	title := payload.Title
	if title == "" {
		title = payload.Message
	}
	if title == "" {
		title = "Generic Incident"
	}

	desc := payload.Description
	if desc == "" {
		desc = title
	}

	extID := payload.ExternalID
	if extID == "" {
		extID = payload.ID
	}
	if extID == "" {
		extID = fmt.Sprintf("gen-%d", time.Now().UnixNano())
	}

	fp := payload.Fingerprint
	if fp == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("generic:%s:%s", service, title)))
		fp = hex.EncodeToString(h[:8])
	}

	env := payload.Environment
	if env == "" {
		env = "production"
	}

	sev := models.SeverityHigh
	switch strings.ToLower(payload.Severity) {
	case "critical":
		sev = models.SeverityCritical
	case "medium", "warn", "warning":
		sev = models.SeverityMedium
	case "low", "info":
		sev = models.SeverityLow
	}

	event := models.IncidentEvent{
		Source:         models.SourceGeneric,
		ExternalID:     extID,
		Fingerprint:    fp,
		Service:        service,
		Environment:    env,
		Title:          title,
		Description:    desc,
		Severity:       sev,
		TriggeredAt:    time.Now().UTC(),
		StacktraceHint: payload.Stacktrace,
		Labels:         payload.Labels,
		IsResolved:     payload.IsResolved,
	}

	return []models.IncidentEvent{event}, nil
}
