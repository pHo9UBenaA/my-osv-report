package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PyPIClient is an HTTP client for the PyPI API.
type PyPIClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewPyPIClient creates a new PyPI API client.
func NewPyPIClient(baseURL string) *PyPIClient {
	return &PyPIClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

// GetDownloads fetches the weekly download count for a package.
func (c *PyPIClient) GetDownloads(ctx context.Context, packageName string) (int, error) {
	url := fmt.Sprintf("%s/pypi/%s/json", c.baseURL, packageName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Info struct {
			Downloads struct {
				LastWeek int `json:"last_week"`
			} `json:"downloads"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.Info.Downloads.LastWeek, nil
}
