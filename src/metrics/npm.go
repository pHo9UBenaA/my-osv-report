package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// NpmClient is an HTTP client for the npm registry API.
type NpmClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewNpmClient creates a new npm API client.
func NewNpmClient(baseURL string) *NpmClient {
	return &NpmClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

// GetDownloads fetches the weekly download count for a package.
func (c *NpmClient) GetDownloads(ctx context.Context, packageName string) (int, error) {
	url := fmt.Sprintf("%s/downloads/point/last-week/%s", c.baseURL, packageName)

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
		Downloads int `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.Downloads, nil
}
