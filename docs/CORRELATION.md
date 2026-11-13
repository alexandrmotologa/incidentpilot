# Correlation Scoring

`incidentpilot.correlator.engine.correlate_incident` scores each recent commit on a 0 to 100 scale using five deterministic signals:

1. File path match (up to 45 points): Normalizes stack trace paths (for example `/app/pkg/checkout/checkout.go`) and matches them against repository file paths (`pkg/checkout/checkout.go` gets 45 points; basename-only matches get 32 points).
2. Diff hunk line proximity (up to 25 points): Parses unified diff headers (`@@ -a,b +c,d @@`) into line ranges. A stack frame line inside a modified hunk adds 25 points; a line within 15 lines of a modified hunk adds 15 points.
3. Git blame line match (20 points): Confirms that the commit specifically touched or authored the exact line number reported in the stack trace.
4. Commit recency (up to 15 points): Commits within 1 hour before `triggered_at` receive 15 points, within 6 hours receive 10 points, and within 24 hours receive 5 points.
5. Error and service keyword overlap (up to 15 points): Matches tokens from the error message and service name against the commit message and patch text.

## Top suspects and runbooks

The correlation engine produces a ranked list of candidate commits. The top 3 candidates are presented in the Incident Brief, API, and web dashboard. If no commit correlates with the crash but the failure matches an operational pattern (for example, memory limits or database timeouts), the system attaches prescriptive runbook diagnostics.

## Rollback target selection

When deployment tags or releases are available, `select_rollback_target` skips the release matching the suspect commit SHA and recommends the preceding stable tag (for example `v2.4.1` when `v2.4.2` introduced the regression). If no prior release tag exists, it recommends `<short_sha>~1`.
