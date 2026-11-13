package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/internal/config"
	"github.com/alexandrmotologa/incidentpilot/internal/orchestrator"
	"github.com/alexandrmotologa/incidentpilot/internal/simulator"
	"github.com/alexandrmotologa/incidentpilot/internal/slack"
	"github.com/alexandrmotologa/incidentpilot/internal/storage"
	"github.com/alexandrmotologa/incidentpilot/internal/webhooks"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

//go:embed all:dist/*
var embeddedDist embed.FS

type Server struct {
	cfg   *config.Config
	store *storage.Store
	orch  *orchestrator.Orchestrator
	mux   *http.ServeMux
}

func NewServer(cfg *config.Config, store *storage.Store, orch *orchestrator.Orchestrator) *Server {
	s := &Server{
		cfg:   cfg,
		store: store,
		orch:  orch,
		mux:   http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) routes() {
	// Static embedded UI
	distFS, err := fs.Sub(embeddedDist, "dist")
	if err == nil {
		fileServer := http.FileServer(http.FS(distFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				fileServer.ServeHTTP(w, r)
				return
			}
			// Check if file exists in FS
			if _, err := fs.Stat(distFS, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
			// Fallback to index.html for SPA routing
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
		})
	}

	// Health check
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]string{
			"status":            "ok",
			"version":           s.cfg.Version,
			"runtime":           "go",
			"incidentpilot_app": "autonomous-sre-responder",
		})
	})

	// API Endpoints
	s.mux.HandleFunc("/api/metrics", s.handleMetrics)
	s.mux.HandleFunc("/api/incidents", s.handleIncidents)
	s.mux.HandleFunc("/api/incidents/", s.handleIncidentByID)
	s.mux.HandleFunc("/api/simulate", s.handleSimulate)
	s.mux.HandleFunc("/api/events", s.handleEventsSSE)

	// Webhooks
	s.mux.HandleFunc("/webhooks/pagerduty", s.handlePagerDuty)
	s.mux.HandleFunc("/webhooks/alertmanager", s.handleAlertmanager)
	s.mux.HandleFunc("/webhooks/sentry", s.handleSentry)
	s.mux.HandleFunc("/webhooks/datadog", s.handleDatadog)
	s.mux.HandleFunc("/webhooks/generic", s.handleGeneric)

	// Slack Interactivity & Events
	s.mux.HandleFunc("/integrations/slack/actions", s.handleSlackActions)
	s.mux.HandleFunc("/integrations/slack/events", s.handleSlackEvents)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metrics, err := s.store.ComputeMetrics(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, metrics)
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil {
			limit = parsed
		}
	}
	service := r.URL.Query().Get("service")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")

	records, err := s.store.ListIncidents(r.Context(), limit, service, severity, status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if records == nil {
		records = []models.IncidentRecord{}
	}
	jsonResponse(w, http.StatusOK, records)
}

func (s *Server) handleIncidentByID(w http.ResponseWriter, r *http.Request) {
	subPath := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
	parts := strings.Split(subPath, "/")
	id := parts[0]

	if id == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	// GET /api/incidents/{id}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		record, err := s.store.GetIncident(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if record == nil {
			http.Error(w, "Incident not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, http.StatusOK, record)
		return
	}

	// Sub-routes: /rollback, /dismiss, /postmortem.md
	switch parts[1] {
	case "rollback":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			TargetVersion string `json:"target_version"`
			RequestedBy   string `json:"requested_by"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.RequestedBy == "" {
			body.RequestedBy = "api-caller"
		}
		rec, rb, err := s.orch.TriggerRollback(r.Context(), id, body.TargetVersion, body.RequestedBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]any{
			"incident": rec,
			"rollback": rb,
		})

	case "dismiss":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Actor string `json:"actor"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Actor == "" {
			body.Actor = "api-caller"
		}
		rec, err := s.orch.DismissIncident(r.Context(), id, body.Actor)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonResponse(w, http.StatusOK, rec)

	case "export-github":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		issueURL, err := s.orch.CreatePostmortemIssue(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{
			"incident_id": id,
			"issue_url":   issueURL,
		})

	case "postmortem.md":
		record, err := s.store.GetIncident(r.Context(), id)
		if err != nil || record == nil {
			http.Error(w, "Incident not found", http.StatusNotFound)
			return
		}
		md := orchestrator.GeneratePostmortemMarkdown(record)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(md))

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Scenario string `json:"scenario"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Scenario == "" {
		body.Scenario = "go_nil_pointer"
	}

	rec, _, err := simulator.RunScenarioSimulation(r.Context(), s.store, s.cfg, body.Scenario, s.orch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, rec)
}

func (s *Server) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	sub := s.orch.SubscribeEvents()
	defer s.orch.UnsubscribeEvents(sub)

	notify := r.Context().Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-notify:
			return
		case msg, ok := <-sub:
			if !ok {
				return
			}
			data, _ := json.Marshal(msg)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, string(data))
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) ingestList(ctx context.Context, events []models.IncidentEvent, syncWait bool) map[string]any {
	var results []map[string]any
	for _, ev := range events {
		rec, deduped, err := s.orch.IngestEvent(ctx, ev, syncWait)
		if err != nil || rec == nil {
			results = append(results, map[string]any{
				"incident_id":  nil,
				"status":       "no_active_incident",
				"deduplicated": false,
			})
			continue
		}
		results = append(results, map[string]any{
			"incident_id":  rec.ID,
			"status":       string(rec.Status),
			"deduplicated": deduped,
			"alert_count":  rec.AlertCount,
		})
	}
	return map[string]any{
		"accepted":  len(results),
		"incidents": results,
	}
}

func (s *Server) handlePagerDuty(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sig := r.Header.Get("X-PagerDuty-Signature")
	if !webhooks.VerifyPagerDutySignature(body, sig, s.cfg.PagerDutySecret) {
		http.Error(w, "Invalid PagerDuty signature", http.StatusUnauthorized)
		return
	}
	events, err := webhooks.ParsePagerDutyWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncWait := r.URL.Query().Get("sync") == "true"
	jsonResponse(w, http.StatusOK, s.ingestList(r.Context(), events, syncWait))
}

func (s *Server) handleAlertmanager(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !webhooks.VerifyBearerToken(auth, s.cfg.AlertmanagerToken) {
		http.Error(w, "Invalid Alertmanager bearer token", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	events, err := webhooks.ParseAlertmanagerWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncWait := r.URL.Query().Get("sync") == "true"
	jsonResponse(w, http.StatusOK, s.ingestList(r.Context(), events, syncWait))
}

func (s *Server) handleSentry(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sig := r.Header.Get("Sentry-Hook-Signature")
	if !webhooks.VerifySentrySignature(body, sig, s.cfg.SentrySecret) {
		http.Error(w, "Invalid Sentry signature", http.StatusUnauthorized)
		return
	}
	events, err := webhooks.ParseSentryWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncWait := r.URL.Query().Get("sync") == "true"
	jsonResponse(w, http.StatusOK, s.ingestList(r.Context(), events, syncWait))
}

func (s *Server) handleDatadog(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("DD-WEBHOOK-TOKEN")
	if !webhooks.VerifyDatadogToken(token, s.cfg.DatadogToken) {
		http.Error(w, "Invalid Datadog token", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	events, err := webhooks.ParseDatadogWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncWait := r.URL.Query().Get("sync") == "true"
	jsonResponse(w, http.StatusOK, s.ingestList(r.Context(), events, syncWait))
}

func (s *Server) handleGeneric(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	events, err := webhooks.ParseGenericWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncWait := r.URL.Query().Get("sync") == "true"
	jsonResponse(w, http.StatusOK, s.ingestList(r.Context(), events, syncWait))
}

func (s *Server) handleSlackActions(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	sig := r.Header.Get("X-Slack-Signature")
	if !webhooks.VerifySlackSignature(body, ts, sig, s.cfg.Notifications.Slack.SigningSecret, 300) {
		http.Error(w, "Invalid Slack signature", http.StatusUnauthorized)
		return
	}

	values, parseErr := url.ParseQuery(string(body))
	payloadRaw := ""
	if parseErr == nil {
		payloadRaw = values.Get("payload")
	}
	if payloadRaw == "" {
		payloadRaw = string(body)
	}

	var slackPayload struct {
		User struct {
			Username string `json:"username"`
			Name     string `json:"name"`
		} `json:"user"`
		ResponseURL string `json:"response_url"`
		Actions     []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}

	if err := json.Unmarshal([]byte(payloadRaw), &slackPayload); err != nil {
		http.Error(w, "Bad Slack payload", http.StatusBadRequest)
		return
	}

	actor := slackPayload.User.Username
	if actor == "" {
		actor = slackPayload.User.Name
	}
	if actor == "" {
		actor = "slack-operator"
	}

	for _, act := range slackPayload.Actions {
		if act.ActionID == "confirm_rollback" {
			parts := strings.SplitN(act.Value, "|", 2)
			incID := parts[0]
			target := ""
			if len(parts) > 1 {
				target = parts[1]
			}
			rec, rb, err := s.orch.TriggerRollback(r.Context(), incID, target, actor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = slack.PostResponseURL(context.Background(), slackPayload.ResponseURL, rec)
			jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "rollback_status": rb.Status})
			return
		} else if act.ActionID == "dismiss_incident" {
			rec, err := s.orch.DismissIncident(r.Context(), act.Value, actor)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = slack.PostResponseURL(context.Background(), slackPayload.ResponseURL, rec)
			jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "status": rec.Status})
			return
		}
	}

	jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "ignored": true})
}

func (s *Server) handleSlackEvents(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	ts := r.Header.Get("X-Slack-Request-Timestamp")
	sig := r.Header.Get("X-Slack-Signature")
	if s.cfg.Notifications.Slack.SigningSecret != "" {
		if !webhooks.VerifySlackSignature(body, ts, sig, s.cfg.Notifications.Slack.SigningSecret, 300) {
			http.Error(w, "Invalid Slack signature", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Event     struct {
			Type     string `json:"type"`
			User     string `json:"user"`
			Text     string `json:"text"`
			Channel  string `json:"channel"`
			Ts       string `json:"ts"`
			ThreadTS string `json:"thread_ts"`
			BotID    string `json:"bot_id"`
		} `json:"event"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}

	// 1. URL Verification challenge for Slack setup
	if req.Type == "url_verification" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"challenge": req.Challenge})
		return
	}

	// 2. Event Callback
	if req.Type == "event_callback" {
		if req.Event.BotID != "" {
			jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "ignored": "bot"})
			return
		}

		threadTS := req.Event.ThreadTS
		if threadTS == "" {
			threadTS = req.Event.Ts
		}

		reply := s.orch.HandleSlackCommand(r.Context(), req.Event.Text, req.Event.Channel, threadTS)
		if reply != "" {
			go func() {
				_ = s.orch.GetSlackClient().ReplyThread(context.Background(), threadTS, reply)
			}()
		}

		jsonResponse(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "ignored": true})
}
