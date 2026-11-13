package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

var errorLevels = map[string]bool{
	"ERROR":    true,
	"ERR":      true,
	"FATAL":    true,
	"PANIC":    true,
	"CRITICAL": true,
	"CRIT":     true,
}

func parseLogTimestamp(raw any) time.Time {
	switch v := raw.(type) {
	case float64:
		if v > 1e15 {
			return time.Unix(0, int64(v)).UTC()
		} else if v > 1e12 {
			return time.UnixMilli(int64(v)).UTC()
		}
		return time.Unix(int64(v), 0).UTC()
	case string:
		cleaned := strings.ReplaceAll(v, "Z", "+00:00")
		if t, err := time.Parse(time.RFC3339Nano, cleaned); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, cleaned); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

type LogCollector interface {
	FetchErrorLogs(ctx context.Context, service string, since, until time.Time) ([]models.LogEntry, error)
}

// JsonlLogCollector reads JSONL or structured plain text files
type JsonlLogCollector struct {
	FilePath string
}

func (c *JsonlLogCollector) FetchErrorLogs(ctx context.Context, service string, since, until time.Time) ([]models.LogEntry, error) {
	file, err := os.Open(c.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var entries []models.LogEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}

		lvl := ""
		if val, ok := m["level"].(string); ok {
			lvl = strings.ToUpper(val)
		} else if val, ok := m["severity"].(string); ok {
			lvl = strings.ToUpper(val)
		}
		if !errorLevels[lvl] {
			continue
		}

		svc := ""
		if val, ok := m["service"].(string); ok {
			svc = val
		} else if val, ok := m["app"].(string); ok {
			svc = val
		}
		if service != "" && svc != "" && svc != service && service != "unknown-service" {
			continue
		}

		tsRaw := m["timestamp"]
		if tsRaw == nil {
			tsRaw = m["ts"]
		}
		if tsRaw == nil {
			tsRaw = m["time"]
		}
		ts := parseLogTimestamp(tsRaw)
		if ts.Before(since) || ts.After(until) {
			continue
		}

		msg := ""
		if val, ok := m["message"].(string); ok {
			msg = val
		} else if val, ok := m["msg"].(string); ok {
			msg = val
		} else if val, ok := m["error"].(string); ok {
			msg = val
		}

		stack := ""
		if val, ok := m["stacktrace"].(string); ok {
			stack = val
		} else if val, ok := m["stack"].(string); ok {
			stack = val
		} else if val, ok := m["trace"].(string); ok {
			stack = val
		}
		if stack == "" && (strings.Contains(msg, "\n") || strings.Contains(msg, ".go:") || strings.Contains(msg, ".py")) {
			stack = msg
		}

		traceID := ""
		if val, ok := m["trace_id"].(string); ok {
			traceID = val
		}

		entries = append(entries, models.LogEntry{
			Timestamp:  ts,
			Level:      lvl,
			Service:    svc,
			Message:    msg,
			TraceID:    traceID,
			Stacktrace: stack,
			Metadata:   m,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// LokiLogCollector queries Loki HTTP query_range
type LokiLogCollector struct {
	BaseURL string
	Client  *http.Client
}

func (l *LokiLogCollector) FetchErrorLogs(ctx context.Context, service string, since, until time.Time) ([]models.LogEntry, error) {
	if l.BaseURL == "" {
		return nil, nil
	}
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	query := fmt.Sprintf(`{service="%s"} |~ "(?i)(error|fatal|panic|exception)"`, service)
	u, err := url.Parse(strings.TrimRight(l.BaseURL, "/") + "/loki/api/v1/query_range")
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(since.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(until.UnixNano(), 10))
	q.Set("limit", "500")
	q.Set("direction", "BACKWARD")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki returned status %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	var entries []models.LogEntry
	for _, stream := range payload.Data.Result {
		svc := stream.Stream["service"]
		if svc == "" {
			svc = service
		}
		for _, val := range stream.Values {
			if len(val) < 2 {
				continue
			}
			tsNs, _ := strconv.ParseInt(val[0], 10, 64)
			ts := time.Unix(0, tsNs).UTC()
			rawLine := val[1]

			msg := rawLine
			stack := ""
			lvl := "ERROR"

			var parsed map[string]any
			if err := json.Unmarshal([]byte(rawLine), &parsed); err == nil {
				if v, ok := parsed["level"].(string); ok {
					lvl = strings.ToUpper(v)
				}
				if v, ok := parsed["message"].(string); ok {
					msg = v
				}
				if v, ok := parsed["stacktrace"].(string); ok {
					stack = v
				}
			} else if strings.Contains(rawLine, "\n") || strings.Contains(rawLine, ".go:") || strings.Contains(rawLine, "Traceback") {
				stack = rawLine
			}

			entries = append(entries, models.LogEntry{
				Timestamp:  ts,
				Level:      lvl,
				Service:    svc,
				Message:    msg,
				Stacktrace: stack,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}
