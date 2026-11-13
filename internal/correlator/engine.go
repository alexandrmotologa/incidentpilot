package correlator

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexandrmotologa/incidentpilot/internal/collectors"
	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func pathsMatch(framePath, commitFilePath string) (matched bool, exactSuffix bool) {
	fNorm := collectors.NormalizeFilePath(framePath)
	cNorm := collectors.NormalizeFilePath(commitFilePath)
	if fNorm == "" || cNorm == "" {
		return false, false
	}
	if fNorm == cNorm || strings.HasSuffix(fNorm, "/"+cNorm) || strings.HasSuffix(cNorm, "/"+fNorm) {
		return true, true
	}
	if filepath.Base(fNorm) == filepath.Base(cNorm) {
		return true, false
	}
	return false, false
}

func isCommitMatch(suspect *models.CommitInfo, commitSHA string) bool {
	if suspect == nil || commitSHA == "" {
		return false
	}
	sSHA := strings.ToLower(strings.TrimSpace(suspect.SHA))
	sShort := strings.ToLower(strings.TrimSpace(suspect.ShortSHA))
	cSHA := strings.ToLower(strings.TrimSpace(commitSHA))

	if sSHA != "" && (strings.HasPrefix(sSHA, cSHA) || strings.HasPrefix(cSHA, sSHA)) {
		return true
	}
	if sShort != "" && (strings.HasPrefix(cSHA, sShort) || strings.HasPrefix(sShort, cSHA)) {
		return true
	}
	return false
}

func SelectRollbackTarget(deployments []models.DeploymentInfo, suspectCommit *models.CommitInfo) string {
	if len(deployments) >= 2 {
		for i, dep := range deployments {
			if suspectCommit != nil && dep.CommitSHA != "" && isCommitMatch(suspectCommit, dep.CommitSHA) {
				continue
			}
			// If this is the current active deployment (first in list) and suspect wasn't matched explicitly,
			// the safe rollback target should be the previous release
			if i == 0 && suspectCommit != nil {
				continue
			}
			if dep.Version != "" {
				return dep.Version
			}
			return dep.Tag
		}
		if deployments[1].Version != "" {
			return deployments[1].Version
		}
		return deployments[1].Tag
	}
	if len(deployments) == 1 {
		dep := deployments[0]
		if suspectCommit != nil && dep.CommitSHA != "" && !strings.HasPrefix(suspectCommit.SHA, dep.CommitSHA) {
			if dep.Version != "" {
				return dep.Version
			}
			return dep.Tag
		}
		if suspectCommit != nil {
			return suspectCommit.ShortSHA + "~1"
		}
		if dep.Version != "" {
			return dep.Version
		}
		return dep.Tag
	}
	if suspectCommit != nil {
		return suspectCommit.ShortSHA + "~1"
	}
	return "previous-stable"
}

func CorrelateIncident(
	event models.IncidentEvent,
	logs []models.LogEntry,
	stacktraces []*models.ParsedStackTrace,
	commits []models.CommitInfo,
	deployments []models.DeploymentInfo,
	blameSHAs map[string]bool,
) []models.CorrelationCandidate {
	if len(commits) == 0 {
		return nil
	}

	var errorTextParts []string
	errorTextParts = append(errorTextParts, event.Title, event.Description, event.Service)
	for i, st := range stacktraces {
		if i >= 3 {
			break
		}
		errorTextParts = append(errorTextParts, st.ErrorType, st.ErrorMessage)
	}
	for i, log := range logs {
		if i >= 5 {
			break
		}
		errorTextParts = append(errorTextParts, log.Message)
	}
	errorText := strings.ToLower(strings.Join(errorTextParts, " "))

	var allFrames []models.StackFrame
	for _, st := range stacktraces {
		allFrames = append(allFrames, st.Frames...)
	}

	var candidates []models.CorrelationCandidate

	for _, commit := range commits {
		score := 0.0
		var reasons []string
		var matchedFiles []string
		var matchedLines []string

		bestFilePts := 0.0
		bestLinePts := 0.0

		for _, fdiff := range commit.Files {
			for _, frame := range allFrames {
				matched, exactSuffix := pathsMatch(frame.File, fdiff.Path)
				if !matched {
					continue
				}

				foundFile := false
				for _, mf := range matchedFiles {
					if mf == fdiff.Path {
						foundFile = true
						break
					}
				}
				if !foundFile {
					matchedFiles = append(matchedFiles, fdiff.Path)
				}

				filePts := 32.0
				if exactSuffix {
					filePts = 45.0
				}
				if filePts > bestFilePts {
					bestFilePts = filePts
				}

				if frame.Line > 0 && len(fdiff.ChangedLineRanges) > 0 {
					for _, lr := range fdiff.ChangedLineRanges {
						if frame.Line >= lr.Start && frame.Line <= lr.End {
							if bestLinePts < 25.0 {
								bestLinePts = 25.0
							}
							matchedLines = append(matchedLines, fdiff.Path)
						} else if absInt(frame.Line-lr.Start) <= 15 || absInt(frame.Line-lr.End) <= 15 {
							if bestLinePts < 15.0 {
								bestLinePts = 15.0
							}
							matchedLines = append(matchedLines, fdiff.Path)
						}
					}
				}
			}
		}

		if bestFilePts > 0 {
			score += bestFilePts
			reasons = append(reasons, "Modified stack trace file(s): "+strings.Join(matchedFiles, ", "))
		}
		if bestLinePts > 0 {
			score += bestLinePts
			reasons = append(reasons, "Diff hunk overlaps crash location in: "+strings.Join(matchedLines, ", "))
		}

		// Git blame match boost
		if len(blameSHAs) > 0 {
			for bSHA := range blameSHAs {
				if strings.HasPrefix(commit.SHA, bSHA) || strings.HasPrefix(bSHA, commit.ShortSHA) {
					score += 20.0
					reasons = append(reasons, "git blame confirms commit authored the exact crashing line")
					break
				}
			}
		}

		// Recency
		ageHours := event.TriggeredAt.Sub(commit.Timestamp).Hours()
		if ageHours >= 0 && ageHours <= 1.0 {
			score += 15.0
			reasons = append(reasons, "Committed within 1 hour before incident")
		} else if ageHours > 1.0 && ageHours <= 6.0 {
			score += 10.0
			reasons = append(reasons, "Committed within 6 hours before incident")
		} else if ageHours > 6.0 && ageHours <= 24.0 {
			score += 5.0
			reasons = append(reasons, "Committed within 24 hours before incident")
		}

		// Keyword overlap
		msgLower := strings.ToLower(commit.Message)
		keywords := []string{"panic", "nil", "null", "pointer", "timeout", "checkout", "billing", "payment", strings.ToLower(event.Service)}
		hits := 0
		for _, kw := range keywords {
			if len(kw) >= 3 && strings.Contains(errorText, kw) && strings.Contains(msgLower, kw) {
				hits++
			}
		}
		if hits > 0 {
			pts := float64(hits) * 5.0
			if pts > 15.0 {
				pts = 15.0
			}
			score += pts
			reasons = append(reasons, "Commit message shares error/service keywords")
		}

		if score > 100.0 {
			score = 100.0
		}

		if score > 0 {
			candidates = append(candidates, models.CorrelationCandidate{
				Commit:         commit,
				Score:          score,
				Reasons:        reasons,
				MatchedFiles:   matchedFiles,
				MatchedLines:   matchedLines,
				RollbackTarget: SelectRollbackTarget(deployments, &commit),
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	return candidates
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
