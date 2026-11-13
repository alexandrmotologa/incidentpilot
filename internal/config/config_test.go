package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoadAndEnvExpansion(t *testing.T) {
	os.Setenv("TEST_SLACK_WEBHOOK", "https://hooks.slack.com/services/TEST/123")
	defer os.Unsetenv("TEST_SLACK_WEBHOOK")

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test_config.yaml")

	yamlContent := `
version: "1"
host: "127.0.0.1"
port: 9090
notifications:
  slack:
    webhook_url: "${TEST_SLACK_WEBHOOK}"
    channel: "#test-channel"
services:
  - name: "checkout-api"
    repo: "acme/checkout"
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Host != "127.0.0.1" || cfg.Port != 9090 {
		t.Errorf("expected host 127.0.0.1 and port 9090, got %s:%d", cfg.Host, cfg.Port)
	}
	if cfg.Notifications.Slack.WebhookURL != "https://hooks.slack.com/services/TEST/123" {
		t.Errorf("env var was not expanded, got: %s", cfg.Notifications.Slack.WebhookURL)
	}
	svc := cfg.GetService("checkout-api")
	if svc == nil || svc.Repo != "acme/checkout" {
		t.Errorf("expected service checkout-api with repo acme/checkout")
	}
}
