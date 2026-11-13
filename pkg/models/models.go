package models

import (
	"time"
)

type AlertSource string

const (
	SourcePagerDuty    AlertSource = "pagerduty"
	SourceAlertmanager AlertSource = "alertmanager"
	SourceSentry       AlertSource = "sentry"
	SourceDatadog      AlertSource = "datadog"
	SourceGeneric      AlertSource = "generic"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type IncidentStatus string

const (
	StatusInvestigating    IncidentStatus = "investigating"
	StatusBriefSent        IncidentStatus = "brief_sent"
	StatusRollbackPending  IncidentStatus = "rollback_pending"
	StatusMitigating       IncidentStatus = "mitigating"
	StatusRolledBack       IncidentStatus = "rolled_back"
	StatusVerifiedHealthy  IncidentStatus = "verified_healthy"
	StatusEscalated        IncidentStatus = "escalated"
	StatusRollbackFailed   IncidentStatus = "rollback_failed"
	StatusDismissed        IncidentStatus = "dismissed"
	StatusResolved         IncidentStatus = "resolved"
)

type IncidentEvent struct {
	Source          AlertSource       `json:"source"`
	ExternalID      string            `json:"external_id"`
	Fingerprint     string            `json:"fingerprint"`
	Service         string            `json:"service"`
	Environment     string            `json:"environment"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        Severity          `json:"severity"`
	TriggeredAt     time.Time         `json:"triggered_at"`
	StacktraceHint  string            `json:"stacktrace_hint"`
	Labels          map[string]string `json:"labels"`
	RawPayload      any               `json:"raw_payload,omitempty"`
	IsResolved      bool              `json:"is_resolved"`
}

type StackFrame struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
	Language string `json:"language"`
	Raw      string `json:"raw"`
}

type ParsedStackTrace struct {
	ErrorType    string       `json:"error_type"`
	ErrorMessage string       `json:"error_message"`
	Language     string       `json:"language"`
	Frames       []StackFrame `json:"frames"`
}

type LogEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Level      string         `json:"level"`
	Service    string         `json:"service"`
	Message    string         `json:"message"`
	TraceID    string         `json:"trace_id"`
	Stacktrace string         `json:"stacktrace"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type MetricSample struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Query     string    `json:"query"`
}

type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type FileDiff struct {
	Path               string      `json:"path"`
	Additions          int         `json:"additions"`
	Deletions          int         `json:"deletions"`
	Patch              string      `json:"patch"`
	ChangedLineRanges  []LineRange `json:"changed_line_ranges"`
}

type CommitInfo struct {
	SHA       string     `json:"sha"`
	ShortSHA  string     `json:"short_sha"`
	Author    string     `json:"author"`
	Email     string     `json:"email"`
	Message   string     `json:"message"`
	Timestamp time.Time  `json:"timestamp"`
	Files     []FileDiff `json:"files"`
	URL       string     `json:"url"`
}

type DeploymentInfo struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	Tag         string    `json:"tag"`
	CommitSHA   string    `json:"commit_sha"`
	Environment string    `json:"environment"`
	CreatedAt   time.Time `json:"created_at"`
	Status      string    `json:"status"`
}

type CorrelationCandidate struct {
	Commit         CommitInfo `json:"commit"`
	Score          float64    `json:"score"`
	Reasons        []string   `json:"reasons"`
	MatchedFiles   []string   `json:"matched_files"`
	MatchedLines   []string   `json:"matched_lines"`
	RollbackTarget string     `json:"rollback_target"`
}

type RunbookMatch struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	MatchedPattern string   `json:"matched_pattern"`
	Steps          []string `json:"steps"`
}

type IncidentBrief struct {
	IncidentID              string                 `json:"incident_id"`
	Summary                 string                 `json:"summary"`
	ProbableCause           string                 `json:"probable_cause"`
	Recommendation          string                 `json:"recommendation"`
	RollbackTarget          string                 `json:"rollback_target"`
	Confidence              float64                `json:"confidence"`
	Evidence                []string               `json:"evidence"`
	ErrorCount15m           int                    `json:"error_count_15m"`
	BaselineErrorCount45m   int                    `json:"baseline_error_count_45m"`
	ErrorSpikeRatio         *float64               `json:"error_spike_ratio,omitempty"`
	TopStacktrace           *ParsedStackTrace      `json:"top_stacktrace,omitempty"`
	TopCandidate            *CorrelationCandidate  `json:"top_candidate,omitempty"`
	Candidates              []CorrelationCandidate `json:"candidates,omitempty"`
	MatchedRunbooks         []RunbookMatch         `json:"matched_runbooks,omitempty"`
	InvestigationDurationMs int64                  `json:"investigation_duration_ms"`
	SynthesisMode           string                 `json:"synthesis_mode"`
}

type TimelineStep struct {
	Timestamp  time.Time `json:"timestamp"`
	Stage      string    `json:"stage"`
	Detail     string    `json:"detail"`
	DurationMs int64     `json:"duration_ms"`
}

type RollbackRecord struct {
	ID            string    `json:"id"`
	IncidentID    string    `json:"incident_id"`
	TargetVersion string    `json:"target_version"`
	Provider      string    `json:"provider"`
	Status        string    `json:"status"`
	RequestedBy   string    `json:"requested_by"`
	ExecutedAt    time.Time `json:"executed_at"`
	Output        string    `json:"output"`
	Error         string    `json:"error"`
}

type HealthVerificationRecord struct {
	Status           string     `json:"status"` // "in_progress", "healthy", "unhealthy"
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	InitialErrorRate float64    `json:"initial_error_rate"`
	FinalErrorRate   float64    `json:"final_error_rate"`
	Samples          []float64  `json:"samples"`
	Detail           string     `json:"detail"`
}

type AutoRollbackPolicy struct {
	Enabled             bool     `json:"enabled" yaml:"enabled"`
	Environments        []string `json:"environments" yaml:"environments"`
	MinConfidence       float64  `json:"min_confidence" yaml:"min_confidence"`
	MinSpikeRatio       float64  `json:"min_spike_ratio" yaml:"min_spike_ratio"`
	MaxRollbackAgeHours int      `json:"max_rollback_age_hours" yaml:"max_rollback_age_hours"`
}

type IncidentRecord struct {
	ID                 string                    `json:"id"`
	Event              IncidentEvent             `json:"event"`
	Status             IncidentStatus            `json:"status"`
	AlertCount         int                       `json:"alert_count"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
	ResolvedAt         *time.Time                `json:"resolved_at,omitempty"`
	MTTRSeconds        *float64                  `json:"mttr_seconds,omitempty"`
	Brief              *IncidentBrief            `json:"brief,omitempty"`
	Timeline           []TimelineStep            `json:"timeline"`
	Rollbacks          []RollbackRecord          `json:"rollbacks"`
	SlackMessageTS     string                    `json:"slack_message_ts,omitempty"`
	PostmortemURL      string                    `json:"postmortem_url,omitempty"`
	HealthVerification *HealthVerificationRecord `json:"health_verification,omitempty"`
}

type SreMetrics struct {
	TotalIncidents     int      `json:"total_incidents"`
	ActiveIncidents    int      `json:"active_incidents"`
	ResolvedIncidents  int      `json:"resolved_incidents"`
	AvgInvestigationMs float64  `json:"avg_investigation_ms"`
	AvgMTTRSeconds     *float64 `json:"avg_mttr_seconds"`
	CorrelationHitRate float64  `json:"correlation_hit_rate"`
}
