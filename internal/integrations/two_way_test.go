package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTwoWayClientIntegrations(t *testing.T) {
	var pdAckReceived, pdNoteReceived, sentryCommentReceived, ghIssueReceived bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		if strings.Contains(r.URL.Path, "/incidents/pd-123/notes") {
			pdNoteReceived = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"note":{"id":"note-1"}}`))
			return
		}

		if strings.Contains(r.URL.Path, "/incidents/pd-123") {
			pdAckReceived = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"incident":{"id":"pd-123","status":"acknowledged"}}`))
			return
		}

		if strings.Contains(r.URL.Path, "/issues/sentry-456/comments") {
			sentryCommentReceived = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"comment-1"}`))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/acme/repo/issues") {
			ghIssueReceived = true
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)
			if payload["title"] != "Test Postmortem" {
				t.Errorf("unexpected issue title: %v", payload["title"])
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/acme/repo/issues/42"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	cli := &TwoWayClient{
		HTTPClient:       ts.Client(),
		BasePagerDutyURL: ts.URL,
		BaseSentryURL:    ts.URL,
		BaseGitHubURL:    ts.URL,
	}

	ctx := context.Background()

	// 1. PagerDuty Ack
	if err := cli.PagerDutyAcknowledge(ctx, "pd-token", "pd-123", "sre@test.com"); err != nil {
		t.Fatalf("PagerDutyAcknowledge failed: %v", err)
	}
	if !pdAckReceived {
		t.Error("PagerDuty acknowledge was not called")
	}

	// 2. PagerDuty Note
	if err := cli.PagerDutyAddNote(ctx, "pd-token", "pd-123", "sre@test.com", "Investigating issue"); err != nil {
		t.Fatalf("PagerDutyAddNote failed: %v", err)
	}
	if !pdNoteReceived {
		t.Error("PagerDuty add note was not called")
	}

	// 3. Sentry Comment
	if err := cli.SentryAddComment(ctx, "sentry-token", "sentry-456", "Root cause identified"); err != nil {
		t.Fatalf("SentryAddComment failed: %v", err)
	}
	if !sentryCommentReceived {
		t.Error("Sentry add comment was not called")
	}

	// 4. GitHub Postmortem Issue
	issueURL, err := cli.CreateGitHubPostmortemIssue(ctx, "gh-token", "acme/repo", "Test Postmortem", "## Body")
	if err != nil {
		t.Fatalf("CreateGitHubPostmortemIssue failed: %v", err)
	}
	if !ghIssueReceived || issueURL != "https://github.com/acme/repo/issues/42" {
		t.Errorf("expected issue url, got %s", issueURL)
	}

	// 5. Test empty token safe fallback
	if err := cli.PagerDutyAcknowledge(ctx, "", "pd-1", ""); err != nil {
		t.Errorf("expected nil for empty token, got: %v", err)
	}
	if err := cli.SentryAddComment(ctx, "", "sentry-1", "note"); err != nil {
		t.Errorf("expected nil for empty token, got: %v", err)
	}
}
