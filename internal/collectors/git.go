package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@`)

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return t.UTC()
	}
	t, err = time.Parse(time.RFC3339, raw)
	if err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func parseChangedLineRanges(patch string) []models.LineRange {
	var ranges []models.LineRange
	for _, line := range strings.Split(patch, "\n") {
		m := hunkRe.FindStringSubmatch(line)
		if len(m) > 1 {
			start, _ := strconv.Atoi(m[1])
			count := 1
			if len(m) > 2 && m[2] != "" {
				count, _ = strconv.Atoi(m[2])
			}
			end := start
			if count > 1 {
				end = start + count - 1
			}
			ranges = append(ranges, models.LineRange{Start: start, End: end})
		}
	}
	return ranges
}

type GitProvider interface {
	FetchRecentCommits(ctx context.Context, since time.Time, limit int) ([]models.CommitInfo, error)
	FetchRecentDeployments(ctx context.Context, environment string, limit int) ([]models.DeploymentInfo, error)
	BlameLine(ctx context.Context, filePath string, line int) (string, error)
}

type LocalGitProvider struct {
	RepoPath string
}

func (l *LocalGitProvider) runGit(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", l.RepoPath}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (l *LocalGitProvider) FetchRecentCommits(ctx context.Context, since time.Time, limit int) ([]models.CommitInfo, error) {
	if limit <= 0 {
		limit = 25
	}
	sinceISO := since.UTC().Format(time.RFC3339)
	out, err := l.runGit(ctx, "log", fmt.Sprintf("-n%d", limit), fmt.Sprintf("--since=%s", sinceISO), "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%s")
	if err != nil || strings.TrimSpace(out) == "" {
		out, err = l.runGit(ctx, "log", "-n10", "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%aI%x1f%s")
		if err != nil {
			return nil, nil
		}
	}

	var commits []models.CommitInfo
	for _, row := range strings.Split(out, "\n") {
		parts := strings.Split(row, "\x1f")
		if len(parts) < 6 {
			continue
		}
		sha := parts[0]
		shortSHA := parts[1]
		author := parts[2]
		email := parts[3]
		ts := parseTime(parts[4])
		msg := parts[5]

		diffText, _ := l.runGit(ctx, "show", "--unified=3", "--no-color", "--format=", sha)
		files := parseGitShowDiff(diffText)

		commits = append(commits, models.CommitInfo{
			SHA:       sha,
			ShortSHA:  shortSHA,
			Author:    author,
			Email:     email,
			Message:   msg,
			Timestamp: ts,
			Files:     files,
		})
	}

	return commits, nil
}

func parseGitShowDiff(diffText string) []models.FileDiff {
	var files []models.FileDiff
	var currentPath string
	var patchLines []string
	additions := 0
	deletions := 0

	flush := func() {
		if currentPath != "" {
			patch := strings.Join(patchLines, "\n")
			files = append(files, models.FileDiff{
				Path:              currentPath,
				Additions:         additions,
				Deletions:         deletions,
				Patch:             patch,
				ChangedLineRanges: parseChangedLineRanges(patch),
			})
		}
	}

	for _, line := range strings.Split(diffText, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			currentPath = ""
			patchLines = nil
			additions = 0
			deletions = 0
			parts := strings.Split(line, " b/")
			if len(parts) == 2 {
				currentPath = strings.TrimSpace(parts[1])
			}
		} else if currentPath != "" {
			if strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "index ") {
				continue
			}
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				additions++
			} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				deletions++
			}
			patchLines = append(patchLines, line)
		}
	}
	flush()
	return files
}

func (l *LocalGitProvider) FetchRecentDeployments(ctx context.Context, environment string, limit int) ([]models.DeploymentInfo, error) {
	if limit <= 0 {
		limit = 10
	}
	out, err := l.runGit(ctx, "for-each-ref",
		fmt.Sprintf("--count=%d", limit),
		"--sort=-creatordate",
		"--sort=-v:refname",
		"--format=%(refname:short)|%(*objectname:short)|%(objectname:short)|%(creatordate:iso-strict)",
		"refs/tags",
	)
	if err != nil {
		return nil, nil
	}

	var deployments []models.DeploymentInfo
	for i, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) < 4 {
			continue
		}
		tag := parts[0]
		derefSHA := parts[1]
		objSHA := parts[2]
		ts := parseTime(parts[3])

		commitSHA := derefSHA
		if commitSHA == "" {
			commitSHA = objSHA
		}

		deployments = append(deployments, models.DeploymentInfo{
			ID:          fmt.Sprintf("tag-%d-%s", i, tag),
			Version:     tag,
			Tag:         tag,
			CommitSHA:   commitSHA,
			Environment: environment,
			CreatedAt:   ts,
			Status:      "success",
		})
	}
	return deployments, nil
}

func (l *LocalGitProvider) BlameLine(ctx context.Context, filePath string, line int) (string, error) {
	if line <= 0 {
		return "", nil
	}
	norm := strings.TrimLeft(strings.ReplaceAll(filePath, "\\", "/"), "/")
	parts := strings.Split(norm, "/")

	// Progressively strip leading directory components to handle container paths (e.g. /app/pkg/...)
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], "/")
		out, err := l.runGit(ctx, "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--porcelain", candidate)
		if err == nil && len(out) > 0 {
			firstLine := strings.Split(out, "\n")[0]
			sha := strings.Fields(firstLine)[0]
			if len(sha) >= 7 && !strings.HasPrefix(sha, "^") {
				return sha, nil
			}
		}
	}
	return "", nil
}

type GitHubGitProvider struct {
	Repo   string
	Token  string
	Client *http.Client
}

func (g *GitHubGitProvider) FetchRecentCommits(ctx context.Context, since time.Time, limit int) ([]models.CommitInfo, error) {
	if g.Repo == "" {
		return nil, nil
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	u := fmt.Sprintf("https://api.github.com/repos/%s/commits?since=%s&per_page=%d",
		g.Repo, since.UTC().Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var rawCommits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Author struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				Date  string `json:"date"`
			} `json:"author"`
			Message string `json:"message"`
		} `json:"commit"`
		HTMLURL string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawCommits); err != nil {
		return nil, err
	}

	var commits []models.CommitInfo
	for _, c := range rawCommits {
		short := c.SHA
		if len(short) > 7 {
			short = short[:7]
		}
		firstLine := strings.Split(c.Commit.Message, "\n")[0]
		commits = append(commits, models.CommitInfo{
			SHA:       c.SHA,
			ShortSHA:  short,
			Author:    c.Commit.Author.Name,
			Email:     c.Commit.Author.Email,
			Message:   firstLine,
			Timestamp: parseTime(c.Commit.Author.Date),
			URL:       c.HTMLURL,
		})
	}

	return commits, nil
}

func (g *GitHubGitProvider) FetchRecentDeployments(ctx context.Context, environment string, limit int) ([]models.DeploymentInfo, error) {
	if g.Repo == "" {
		return nil, nil
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	u := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=%d", g.Repo, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var rawReleases []struct {
		ID         any    `json:"id"`
		TagName    string `json:"tag_name"`
		TargetSHA  string `json:"target_commitish"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawReleases); err != nil {
		return nil, err
	}

	var deps []models.DeploymentInfo
	for _, r := range rawReleases {
		deps = append(deps, models.DeploymentInfo{
			ID:          fmt.Sprintf("%v", r.ID),
			Version:     r.TagName,
			Tag:         r.TagName,
			CommitSHA:   r.TargetSHA,
			Environment: environment,
			CreatedAt:   parseTime(r.PublishedAt),
			Status:      "success",
		})
	}
	return deps, nil
}

func (g *GitHubGitProvider) BlameLine(ctx context.Context, filePath string, line int) (string, error) {
	return "", nil
}

func BuildGitProvider(repo, localPath, token string) GitProvider {
	if localPath != "" && localPath != "." {
		return &LocalGitProvider{RepoPath: localPath}
	}
	if repo != "" && strings.Contains(repo, "/") {
		return &GitHubGitProvider{Repo: repo, Token: token}
	}
	abs, err := filepath.Abs(localPath)
	if err == nil {
		return &LocalGitProvider{RepoPath: abs}
	}
	return &LocalGitProvider{RepoPath: "."}
}
