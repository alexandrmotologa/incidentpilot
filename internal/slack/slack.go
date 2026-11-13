package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

func BuildSlackBlocks(record *models.IncidentRecord) []map[string]any {
	brief := record.Brief
	ev := record.Event
	sev := strings.ToUpper(string(ev.Severity))

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("[%s] Incident Brief: %s", sev, ev.Service),
				"emoji": false,
			},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Incident ID:*\n`%s`", record.ID),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Source:*\n%s (%s)", ev.Source, ev.Environment),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Alert:*\n%s", ev.Title),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Investigation Time:*\n%d ms", func() int64 {
						if brief != nil {
							return brief.InvestigationDurationMs
						}
						return 0
					}()),
				},
			},
		},
	}

	if brief != nil {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Probable Cause (%.0f%% confidence):*\n%s\n\n*Recommendation:*\n%s",
					brief.Confidence, brief.ProbableCause, brief.Recommendation),
			},
		})

		if len(brief.Evidence) > 0 {
			var evLines []string
			for i, e := range brief.Evidence {
				if i >= 5 {
					break
				}
				evLines = append(evLines, "- "+e)
			}
			blocks = append(blocks, map[string]any{
				"type": "context",
				"elements": []map[string]any{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Evidence (last 15m: %d errors):*\n%s", brief.ErrorCount15m, strings.Join(evLines, "\n")),
					},
				},
			})
		}

		if record.Status == models.StatusRolledBack {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Status:* Rolled back to `%s`.", brief.RollbackTarget),
				},
			})
		} else if record.Status == models.StatusDismissed {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": "*Status:* Dismissed by on-call engineer.",
				},
			})
		} else if record.Status == models.StatusResolved {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Status:* Resolved (MTTR: %.1f s).", func() float64 {
						if record.MTTRSeconds != nil {
							return *record.MTTRSeconds
						}
						return 0
					}()),
				},
			})
		} else {
			target := brief.RollbackTarget
			if target == "" {
				target = "previous-stable"
			}
			blocks = append(blocks, map[string]any{
				"type":     "actions",
				"block_id": fmt.Sprintf("incident_actions_%s", record.ID),
				"elements": []map[string]any{
					{
						"type":      "button",
						"text":      map[string]any{"type": "plain_text", "text": fmt.Sprintf("Confirm Rollback (%s)", target), "emoji": false},
						"style":     "danger",
						"action_id": "confirm_rollback",
						"value":     fmt.Sprintf("%s|%s", record.ID, target),
						"confirm": map[string]any{
							"title":   map[string]any{"type": "plain_text", "text": "Confirm Rollback"},
							"text":    map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("Roll back *%s* to `%s`?", ev.Service, target)},
							"confirm": map[string]any{"type": "plain_text", "text": "Execute Rollback"},
							"deny":    map[string]any{"type": "plain_text", "text": "Cancel"},
						},
					},
					{
						"type":      "button",
						"text":      map[string]any{"type": "plain_text", "text": "Acknowledge", "emoji": false},
						"action_id": "dismiss_incident",
						"value":     record.ID,
					},
				},
			})
		}
	}

	return blocks
}

type Client struct {
	WebhookURL string
	BotToken   string
	Channel    string
	HTTPClient *http.Client
}

func (c *Client) SendBrief(ctx context.Context, record *models.IncidentRecord) (delivered bool, messageTS string, err error) {
	if c.WebhookURL == "" && c.BotToken == "" {
		return false, "", nil
	}

	blocks := BuildSlackBlocks(record)
	fallbackText := record.Event.Title
	if record.Brief != nil {
		fallbackText = record.Brief.Summary
	}

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	if c.BotToken != "" && c.Channel != "" {
		body := map[string]any{
			"channel": c.Channel,
			"text":    fallbackText,
			"blocks":  blocks,
		}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewBuffer(data))
		if err != nil {
			return false, "", err
		}
		req.Header.Set("Authorization", "Bearer "+c.BotToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return false, "", err
		}
		defer resp.Body.Close()

		var res struct {
			OK bool   `json:"ok"`
			TS string `json:"ts"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return res.OK, res.TS, nil
	}

	if c.WebhookURL != "" {
		body := map[string]any{
			"text":   fallbackText,
			"blocks": blocks,
		}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewBuffer(data))
		if err != nil {
			return false, "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return false, "", err
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK, "", nil
	}

	return false, "", nil
}

func (c *Client) SendMessage(ctx context.Context, text string) error {
	if c.WebhookURL == "" && (c.BotToken == "" || c.Channel == "") {
		return nil
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	if c.BotToken != "" && c.Channel != "" {
		body := map[string]any{
			"channel": c.Channel,
			"text":    text,
		}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.BotToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return nil
	}

	if c.WebhookURL != "" {
		body := map[string]any{"text": text}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return nil
	}
	return nil
}

func (c *Client) ReplyThread(ctx context.Context, threadTS, text string) error {
	if c.BotToken == "" || c.Channel == "" || threadTS == "" {
		return nil
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	body := map[string]any{
		"channel":   c.Channel,
		"text":      text,
		"thread_ts": threadTS,
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.BotToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func PostResponseURL(ctx context.Context, responseURL string, record *models.IncidentRecord) error {
	if responseURL == "" {
		return nil
	}
	blocks := BuildSlackBlocks(record)
	fallback := record.Event.Title
	if record.Brief != nil {
		fallback = record.Brief.Summary
	}
	payload := map[string]any{
		"replace_original": true,
		"text":             fallback,
		"blocks":           blocks,
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
