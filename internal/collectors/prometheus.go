package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
)

type PrometheusCollector struct {
	BaseURL string
	Client  *http.Client
}

func (p *PrometheusCollector) QueryMetricRate(ctx context.Context, query string, t time.Time) (*models.MetricSample, error) {
	if p.BaseURL == "" || query == "" {
		return nil, nil
	}

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	endpoint := strings.TrimRight(p.BaseURL, "/") + "/api/v1/query"
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("query", query)
	q.Set("time", strconv.FormatInt(t.Unix(), 10))
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
		return nil, fmt.Errorf("prometheus returned status %d", resp.StatusCode)
	}

	var payload struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Value []any `json:"value"` // [unix_timestamp, "value_string"]
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	if len(payload.Data.Result) == 0 || len(payload.Data.Result[0].Value) < 2 {
		return nil, nil
	}

	valStr, ok := payload.Data.Result[0].Value[1].(string)
	if !ok {
		return nil, nil
	}

	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return nil, err
	}

	return &models.MetricSample{
		Timestamp: t,
		Value:     val,
		Query:     query,
	}, nil
}
