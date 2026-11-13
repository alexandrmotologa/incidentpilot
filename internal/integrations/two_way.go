package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TwoWayClient struct {
	HTTPClient       *http.Client
	BasePagerDutyURL string
	BaseSentryURL    string
	BaseGitHubURL    string
}

func NewTwoWayClient() *TwoWayClient {
	return &TwoWayClient{
		HTTPClient:       &http.Client{Timeout: 10 * time.Second},
		BasePagerDutyURL: "https://api.pagerduty.com",
		BaseSentryURL:    "https://sentry.io/api/0",
		BaseGitHubURL:    "https://api.github.com",
	}
}

// PagerDuty API: Acknowledge and Add Note
func (c *TwoWayClient) PagerDutyAcknowledge(ctx context.Context, apiToken, incidentID, email string) error {
	if apiToken == "" || incidentID == "" {
		return nil
	}
	base := c.BasePagerDutyURL
	if base == "" {
		base = "https://api.pagerduty.com"
	}
	url := fmt.Sprintf("%s/incidents/%s", base, incidentID)
	payload := map[string]any{
		"incident": map[string]any{
			"type":   "incident_reference",
			"status": "acknowledged",
		},
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+apiToken)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("Content-Type", "application/json")
	if email != "" {
		req.Header.Set("From", email)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *TwoWayClient) PagerDutyAddNote(ctx context.Context, apiToken, incidentID, email, noteContent string) error {
	if apiToken == "" || incidentID == "" || noteContent == "" {
		return nil
	}
	base := c.BasePagerDutyURL
	if base == "" {
		base = "https://api.pagerduty.com"
	}
	url := fmt.Sprintf("%s/incidents/%s/notes", base, incidentID)
	payload := map[string]any{
		"note": map[string]string{
			"content": noteContent,
		},
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+apiToken)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("Content-Type", "application/json")
	if email != "" {
		req.Header.Set("From", email)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Sentry API: Add Comment to Issue
func (c *TwoWayClient) SentryAddComment(ctx context.Context, authToken, issueID, comment string) error {
	if authToken == "" || issueID == "" || comment == "" {
		return nil
	}
	base := c.BaseSentryURL
	if base == "" {
		base = "https://sentry.io/api/0"
	}
	url := fmt.Sprintf("%s/issues/%s/comments/", base, issueID)
	payload := map[string]string{
		"comment": comment,
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// GitHub API: Create Issue with Postmortem
func (c *TwoWayClient) CreateGitHubPostmortemIssue(ctx context.Context, token, repo, title, markdownBody string) (string, error) {
	if token == "" || repo == "" {
		return "", fmt.Errorf("github token and repo required")
	}
	base := c.BaseGitHubURL
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/issues", base, repo)
	payload := map[string]any{
		"title": title,
		"body":  markdownBody,
		"labels": []string{"incident-postmortem", "sre", "p1"},
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var res struct {
		HTMLURL string `json:"html_url"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	return res.HTMLURL, nil
}
