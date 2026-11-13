package rollback

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func TestRollbackWebhook(t *testing.T) {
	secret := "secret-token-123"
	received := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		sigHeader := r.Header.Get("X-IncidentPilot-Signature")
		if !strings.HasPrefix(sigHeader, "sha256=") {
			t.Errorf("missing sha256= prefix in signature: %s", sigHeader)
		}
		expectedMac := hmac.New(sha256.New, []byte(secret))
		expectedMac.Write(body)
		expectedSig := hex.EncodeToString(expectedMac.Sum(nil))
		if sigHeader != "sha256="+expectedSig {
			t.Errorf("signature mismatch: got %s, want %s", sigHeader, "sha256="+expectedSig)
		}

		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		if payload["target_version"] != "v1.2.0" {
			t.Errorf("unexpected target version: %v", payload["target_version"])
		}
		if payload["incident_id"] != "inc-100" {
			t.Errorf("unexpected incident_id: %v", payload["incident_id"])
		}

		received = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer ts.Close()

	executor := &Executor{
		Provider:      "webhook",
		WebhookURL:    ts.URL,
		WebhookSecret: secret,
	}

	rec := &models.IncidentRecord{
		ID: "inc-100",
		Event: models.IncidentEvent{
			Service:     "billing-service",
			Environment: "production",
		},
	}

	rb, err := executor.Execute(context.Background(), rec, "v1.2.0", "alice@company.com")
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if rb.Status != "succeeded" {
		t.Errorf("expected succeeded status, got: %s", rb.Status)
	}
	if !received {
		t.Error("webhook was not received by test server")
	}
}

func TestRollbackLocalGit(t *testing.T) {
	tmpDir := t.TempDir()

	// Initialize git repo
	cmds := [][]string{
		{"git", "-C", tmpDir, "init"},
		{"git", "-C", tmpDir, "config", "user.name", "Tester"},
		{"git", "-C", tmpDir, "config", "user.email", "test@test.local"},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed setup cmd %v: %s", c, string(out))
		}
	}

	// Commit 1 (tag v1.0.0)
	f1 := filepath.Join(tmpDir, "file.txt")
	_ = os.WriteFile(f1, []byte("v1"), 0644)
	_ = exec.Command("git", "-C", tmpDir, "add", ".").Run()
	_ = exec.Command("git", "-C", tmpDir, "commit", "-m", "initial release").Run()
	_ = exec.Command("git", "-C", tmpDir, "tag", "v1.0.0").Run()

	// Commit 2 (bad release)
	_ = os.WriteFile(f1, []byte("v2 with bug"), 0644)
	_ = exec.Command("git", "-C", tmpDir, "add", ".").Run()
	_ = exec.Command("git", "-C", tmpDir, "commit", "-m", "bad release").Run()

	executor := &Executor{
		Provider:      "local_git",
		LocalRepoPath: tmpDir,
	}

	rec := &models.IncidentRecord{
		ID: "inc-git-1",
		Event: models.IncidentEvent{
			Service: "checkout",
		},
	}

	// Rollback to v1.0.0
	rb, err := executor.Execute(context.Background(), rec, "v1.0.0", "sre-lead")
	if err != nil {
		t.Fatalf("git rollback failed: %v", err)
	}
	if rb.Status != "succeeded" {
		t.Errorf("expected succeeded status, got: %s", rb.Status)
	}

	// Verify file content is reverted
	content, _ := os.ReadFile(f1)
	if string(content) != "v1" {
		t.Errorf("expected file.txt to contain 'v1', got %q", string(content))
	}

	// Test non-existent ref
	rbFail, _ := executor.Execute(context.Background(), rec, "non-existent-tag", "sre-lead")
	if rbFail.Status != "failed" || rbFail.Error == "" {
		t.Errorf("expected failed status with error message, got: %+v", rbFail)
	}
}
