export interface StackFrame {
  file: string;
  line: number;
  function: string;
  language: string;
  raw: string;
}

export interface ParsedStackTrace {
  error_type: string;
  error_message: string;
  language: string;
  frames: StackFrame[];
}

export interface FileDiff {
  path: string;
  additions: number;
  deletions: number;
  patch: string;
}

export interface CommitInfo {
  sha: string;
  short_sha: string;
  author: string;
  email: string;
  message: string;
  timestamp: string;
  files: FileDiff[];
  url: string;
}

export interface CorrelationCandidate {
  commit: CommitInfo;
  score: number;
  reasons: string[];
  matched_files: string[];
  matched_lines: string[];
  rollback_target: string;
}

export interface RunbookMatch {
  id: string;
  title: string;
  matched_pattern: string;
  steps: string[];
}

export interface IncidentBrief {
  incident_id: string;
  summary: string;
  probable_cause: string;
  recommendation: string;
  rollback_target: string;
  confidence: number;
  evidence: string[];
  error_count_15m: number;
  baseline_error_count_45m: number;
  error_spike_ratio?: number;
  top_stacktrace?: ParsedStackTrace;
  top_candidate?: CorrelationCandidate;
  candidates?: CorrelationCandidate[];
  matched_runbooks?: RunbookMatch[];
  investigation_duration_ms: number;
  synthesis_mode: string;
}

export interface TimelineStep {
  timestamp: string;
  stage: string;
  detail: string;
  duration_ms: number;
}

export interface RollbackRecord {
  id: string;
  incident_id: string;
  target_version: string;
  provider: string;
  status: string;
  requested_by: string;
  executed_at: string;
  output: string;
  error: string;
}

export interface IncidentEvent {
  source: string;
  external_id: string;
  fingerprint: string;
  service: string;
  environment: string;
  title: string;
  description: string;
  severity: string;
  triggered_at: string;
  stacktrace_hint: string;
  labels: Record<string, string>;
  is_resolved: boolean;
}

export interface HealthVerificationRecord {
  status: string;
  started_at: string;
  completed_at?: string;
  initial_error_rate: number;
  final_error_rate: number;
  detail: string;
}

export interface IncidentRecord {
  id: string;
  event: IncidentEvent;
  status: string;
  alert_count: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  mttr_seconds?: number;
  brief?: IncidentBrief;
  timeline: TimelineStep[];
  rollbacks: RollbackRecord[];
  postmortem_url?: string;
  health_verification?: HealthVerificationRecord;
}

export interface SreMetrics {
  total_incidents: number;
  active_incidents: number;
  resolved_incidents: number;
  avg_investigation_ms: number;
  avg_mttr_seconds?: number;
  correlation_hit_rate: number;
}
