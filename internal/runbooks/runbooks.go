package runbooks

import (
	"os"
	"regexp"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	"gopkg.in/yaml.v3"
)

type RunbookDefinition struct {
	ID      string   `yaml:"id"`
	Title   string   `yaml:"title"`
	Pattern string   `yaml:"pattern"`
	Steps   []string `yaml:"steps"`
}

type RunbookFile struct {
	Runbooks []RunbookDefinition `yaml:"runbooks"`
}

var defaultRunbooks = []RunbookDefinition{
	{
		ID:      "oom-killed",
		Title:   "Container OOMKilled / Memory Exhaustion",
		Pattern: `(?i)(oomkilled|out of memory|cannot allocate memory|exit code 137|memory limit)`,
		Steps: []string{
			"Check pod memory usage and recent heap allocation changes (`kubectl top pods`).",
			"Inspect memory limits in deployment manifests and compare against p99 RSS.",
			"Capture a heap profile before restarting or scaling replicas horizontally.",
		},
	},
	{
		ID:      "db-pool-exhausted",
		Title:   "Database Connection Pool Exhaustion",
		Pattern: `(?i)(connection pool|too many connections|remaining connection slots|pool timeout|acquire connection)`,
		Steps: []string{
			"Check active vs idle database connections (`pg_stat_activity` or pool metrics).",
			"Look for unclosed transactions or long-running queries blocking pool release.",
			"Temporarily raise pool max connections or shed non-critical background workers.",
		},
	},
	{
		ID:      "disk-full",
		Title:   "Disk Full / No Space Left on Device",
		Pattern: `(?i)(no space left on device|enospc|disk full|volume full)`,
		Steps: []string{
			"Check filesystem and inode usage (`df -h` and `df -i`).",
			"Clear rotated logs or orphaned temporary artifacts and verify log rotation.",
			"Expand persistent volume claim if data growth is legitimate.",
		},
	},
	{
		ID:      "tls-expired",
		Title:   "TLS Certificate Expired or Handshake Failure",
		Pattern: `(?i)(certificate has expired|x509|tls handshake|ssl_error|cert_authority_invalid)`,
		Steps: []string{
			"Inspect certificate expiry with `openssl s_client -connect <host>:443`.",
			"Check cert-manager / ACME renewal logs and force certificate rotation.",
			"Reload ingress controller or load balancer after renewing the secret.",
		},
	},
	{
		ID:      "upstream-rate-limit",
		Title:   "Upstream Rate Limit (HTTP 429)",
		Pattern: `(?i)(429 too many requests|rate limit exceeded|throttlingexception)`,
		Steps: []string{
			"Identify the upstream provider returning 429 and check `Retry-After` headers.",
			"Enable exponential backoff with jitter and inspect recent retry storms.",
			"Verify API quota usage and request a temporary limit increase if needed.",
		},
	},
}

func LoadRunbooks(path string) []RunbookDefinition {
	items := make([]RunbookDefinition, len(defaultRunbooks))
	copy(items, defaultRunbooks)

	if path == "" {
		path = "./runbooks.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return items
	}

	var rf RunbookFile
	if err := yaml.Unmarshal(data, &rf); err == nil && len(rf.Runbooks) > 0 {
		// Custom runbooks take precedence at front
		items = append(rf.Runbooks, items...)
	}
	return items
}

func MatchRunbooks(event models.IncidentEvent, logs []models.LogEntry, path string) []models.RunbookMatch {
	var corpusParts []string
	corpusParts = append(corpusParts, event.Title, event.Description, event.StacktraceHint)
	for i, l := range logs {
		if i >= 15 {
			break
		}
		corpusParts = append(corpusParts, l.Message)
	}
	corpus := corpusParts[0]
	for _, p := range corpusParts[1:] {
		corpus += "\n" + p
	}

	all := LoadRunbooks(path)
	var matches []models.RunbookMatch
	seen := make(map[string]bool)

	for _, rb := range all {
		if seen[rb.ID] {
			continue
		}
		re, err := regexp.Compile(rb.Pattern)
		if err != nil {
			continue
		}
		loc := re.FindString(corpus)
		if loc != "" {
			seen[rb.ID] = true
			matches = append(matches, models.RunbookMatch{
				ID:             rb.ID,
				Title:          rb.Title,
				MatchedPattern: loc,
				Steps:          rb.Steps,
			})
		}
	}
	return matches
}
