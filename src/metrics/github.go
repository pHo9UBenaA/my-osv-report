package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidGitHubURL = errors.New("invalid github url")

// GitHubClient is an HTTP client for the GitHub API.
type GitHubClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ParseGitHubURL extracts owner and repository name from a GitHub URL.
func ParseGitHubURL(rawURL string) (owner, repo string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", ErrInvalidGitHubURL
	}

	if u.Host != "github.com" {
		return "", "", ErrInvalidGitHubURL
	}

	path := strings.Trim(u.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", ErrInvalidGitHubURL
	}

	return parts[0], parts[1], nil
}

// NewGitHubClient creates a new GitHub API client.
func NewGitHubClient(baseURL, token string) *GitHubClient {
	return &GitHubClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetStars fetches the stargazers count for a repository.
func (c *GitHubClient) GetStars(ctx context.Context, owner, repo string) (int, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
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
		StargazersCount int `json:"stargazers_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.StargazersCount, nil
}
