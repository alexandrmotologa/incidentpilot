package rollback

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	"github.com/google/uuid"
)

type Executor struct {
	Provider        string
	LocalRepoPath   string
	RollbackCommand string
	GitHubRepo      string
	GitHubToken     string
	WorkflowFile    string
	WebhookURL      string
	WebhookSecret   string
}

func (e *Executor) Execute(ctx context.Context, record *models.IncidentRecord, targetVersion, requestedBy string) (*models.RollbackRecord, error) {
	rbID := fmt.Sprintf("rb-%s", uuid.New().String()[:8])
	rb := &models.RollbackRecord{
		ID:            rbID,
		IncidentID:    record.ID,
		TargetVersion: targetVersion,
		Provider:      e.Provider,
		Status:        "succeeded",
		RequestedBy:   requestedBy,
		ExecutedAt:    time.Now().UTC(),
	}

	var out string
	var err error

	switch e.Provider {
	case "github_workflow":
		out, err = e.executeGitHubWorkflow(ctx, record, targetVersion)
	case "webhook":
		out, err = e.executeWebhook(ctx, record, targetVersion, requestedBy)
	default:
		out, err = e.executeLocalGit(ctx, record, targetVersion)
	}

	if err != nil {
		rb.Status = "failed"
		rb.Error = err.Error()
	} else {
		rb.Output = out
	}

	return rb, nil
}

func (e *Executor) executeLocalGit(ctx context.Context, record *models.IncidentRecord, targetVersion string) (string, error) {
	repoPath := e.LocalRepoPath
	if repoPath == "" {
		repoPath = "."
	}
	abs, err := filepath.Abs(repoPath)
	if err == nil {
		repoPath = abs
	}

	if e.RollbackCommand != "" {
		cmdParts := strings.Fields(e.RollbackCommand)
		cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
		cmd.Dir = repoPath
		cmd.Env = append(os.Environ(),
			"INCIDENTPILOT_INCIDENT_ID="+record.ID,
			"INCIDENTPILOT_SERVICE="+record.Event.Service,
			"INCIDENTPILOT_TARGET_VERSION="+targetVersion,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("command execution failed: %s (%w)", string(out), err)
		}
		return strings.TrimSpace(string(out)), nil
	}

	// Default: verify ref and checkout --detach
	verifyCmd := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "--verify", targetVersion)
	verifyOut, err := verifyCmd.Output()
	if err != nil {
		return "", fmt.Errorf("git ref '%s' not found in %s", targetVersion, repoPath)
	}
	targetSHA := strings.TrimSpace(string(verifyOut))

	checkoutCmd := exec.CommandContext(ctx, "git", "-C", repoPath, "checkout", "--detach", targetVersion)
	checkoutOut, err := checkoutCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git checkout failed: %s (%w)", string(checkoutOut), err)
	}

	short := targetSHA
	if len(short) > 7 {
		short = short[:7]
	}
	return fmt.Sprintf("Checked out %s (%s) in %s", targetVersion, short, repoPath), nil
}

func (e *Executor) executeGitHubWorkflow(ctx context.Context, record *models.IncidentRecord, targetVersion string) (string, error) {
	if e.GitHubRepo == "" || e.GitHubToken == "" {
		return "", fmt.Errorf("github_repo and github_token are required for github_workflow provider")
	}
	workflow := e.WorkflowFile
	if workflow == "" {
		workflow = "rollback.yml"
	}

	u := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/%s/dispatches", e.GitHubRepo, workflow)
	payload := map[string]any{
		"ref": "main",
		"inputs": map[string]string{
			"version":     targetVersion,
			"service":     record.Event.Service,
			"incident_id": record.ID,
		},
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+e.GitHubToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("github workflow dispatch returned status %d", resp.StatusCode)
	}
	return fmt.Sprintf("Dispatched GitHub workflow %s for %s", workflow, targetVersion), nil
}

func (e *Executor) executeWebhook(ctx context.Context, record *models.IncidentRecord, targetVersion, requestedBy string) (string, error) {
	if e.WebhookURL == "" {
		return "", fmt.Errorf("rollback_webhook_url is not configured")
	}

	payload := map[string]any{
		"incident_id":    record.ID,
		"service":        record.Event.Service,
		"environment":    record.Event.Environment,
		"target_version": targetVersion,
		"requested_by":   requestedBy,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	if e.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(e.WebhookSecret))
		mac.Write(data)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-IncidentPilot-Signature", "sha256="+sig)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("webhook rollback returned status %d", resp.StatusCode)
	}
	return fmt.Sprintf("Webhook rollback accepted (%d) for %s", resp.StatusCode, targetVersion), nil
}
