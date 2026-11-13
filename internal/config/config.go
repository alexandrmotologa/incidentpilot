package config

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	"gopkg.in/yaml.v3"
)

var envVarRegex = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

type ObservabilityConfig struct {
	LokiURL          string `yaml:"loki_url"`
	PrometheusURL    string `yaml:"prometheus_url"`
	ErrorMetricQuery string `yaml:"error_metric_query"`
	LogFilePath      string `yaml:"log_file_path"`
}

type MitigationConfig struct {
	AllowAutoRollback bool                      `yaml:"allow_auto_rollback"`
	AutoRollback      models.AutoRollbackPolicy `yaml:"auto_rollback"`
	RollbackCommand   string                    `yaml:"rollback_command"`
	RollbackProvider  string                    `yaml:"rollback_provider"`
	RollbackWebhook   string                    `yaml:"rollback_webhook_url"`
}

type ServiceConfig struct {
	Name          string              `yaml:"name"`
	Repo          string              `yaml:"repo"`
	LocalRepoPath string              `yaml:"local_repo_path"`
	GitHubToken   string              `yaml:"github_token"`
	SlackChannel  string              `yaml:"slack_channel"`
	Observability ObservabilityConfig `yaml:"observability"`
	Mitigation    MitigationConfig    `yaml:"mitigation"`
}

type SlackNotificationConfig struct {
	WebhookURL    string `yaml:"webhook_url"`
	BotToken      string `yaml:"bot_token"`
	Channel       string `yaml:"channel"`
	SigningSecret string `yaml:"signing_secret"`
}

type NotificationsConfig struct {
	Slack SlackNotificationConfig `yaml:"slack"`
}

type Config struct {
	Version                    string              `yaml:"version"`
	Host                       string              `yaml:"host"`
	Port                       int                 `yaml:"port"`
	DatabasePath               string              `yaml:"database_path"`
	DedupWindowSeconds         int                 `yaml:"dedup_window_seconds"`
	InvestigationTimeoutSec    int                 `yaml:"investigation_timeout_seconds"`
	LogWindowMinutes           int                 `yaml:"log_window_minutes"`
	GitLookbackHours           int                 `yaml:"git_lookback_hours"`
	LLMAPIURL                  string              `yaml:"llm_api_url"`
	LLMAPIKey                  string              `yaml:"llm_api_key"`
	LLMModel                   string              `yaml:"llm_model"`
	PagerDutySecret            string              `yaml:"pagerduty_webhook_secret"`
	SentrySecret               string              `yaml:"sentry_client_secret"`
	AlertmanagerToken          string              `yaml:"alertmanager_bearer_token"`
	DatadogToken               string              `yaml:"datadog_webhook_token"`
	PagerDutyAPIToken          string              `yaml:"pagerduty_api_token"`
	SentryAuthToken            string              `yaml:"sentry_auth_token"`
	GitHubToken                string              `yaml:"github_token"`
	GitHubRepo                 string              `yaml:"github_repo"`
	HealthCheckDurationSec     int                 `yaml:"health_check_duration_seconds"`
	Services                   []ServiceConfig     `yaml:"services"`
	Notifications              NotificationsConfig `yaml:"notifications"`
	RunbooksPath               string              `yaml:"runbooks_path"`
}

func DefaultConfig() *Config {
	return &Config{
		Version:                 "1",
		Host:                    "0.0.0.0",
		Port:                    8080,
		DatabasePath:            "./data/incidentpilot.db",
		DedupWindowSeconds:      300,
		InvestigationTimeoutSec: 55,
		LogWindowMinutes:        15,
		GitLookbackHours:        48,
		HealthCheckDurationSec:  30,
		LLMModel:                "gpt-4o-mini",
		RunbooksPath:            "./runbooks.yaml",
	}
}

func expandEnv(s string) string {
	return envVarRegex.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarRegex.FindStringSubmatch(match)
		if len(sub) == 2 {
			return os.Getenv(sub[1])
		}
		return match
	})
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		path = "./incidentpilot.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	expanded := expandEnv(string(data))
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, err
	}

	if cfg.DatabasePath != ":memory:" {
		dir := filepath.Dir(cfg.DatabasePath)
		_ = os.MkdirAll(dir, 0755)
	}

	return cfg, nil
}

func (c *Config) GetService(name string) *ServiceConfig {
	for i := range c.Services {
		if c.Services[i].Name == name {
			return &c.Services[i]
		}
	}
	return nil
}
