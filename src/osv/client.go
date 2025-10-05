package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// ErrNotFound is returned when a vulnerability is not found (404).
var ErrNotFound = errors.New("not found")

// ErrBadRequest is returned when the request is invalid (400).
var ErrBadRequest = errors.New("bad request")

// ErrTooManyRequests is returned when rate limit is exceeded (429).
var ErrTooManyRequests = errors.New("too many requests")

// Package represents a package in an affected entry.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Event represents a version event in a range.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Range represents a version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Affected represents affected packages and versions.
type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges,omitempty"`
}

// Severity represents severity information.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference represents a reference link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Vulnerability represents a vulnerability from the OSV API.
type Vulnerability struct {
	ID         string      `json:"id"`
	Modified   time.Time   `json:"modified"`
	Published  time.Time   `json:"published,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
	Severity   []Severity  `json:"severity,omitempty"`
	References []Reference `json:"references,omitempty"`
}

// Client is an HTTP client for the OSV API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	limiter    *rate.Limiter
}

// NewClient creates a new OSV API client without rate limiting.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		limiter: nil,
	}
}

// NewClientWithRateLimit creates a new OSV API client with rate limiting.
// ratePerSecond specifies the maximum number of requests per second.
func NewClientWithRateLimit(baseURL string, ratePerSecond float64) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(ratePerSecond), 1),
	}
}

// NewClientWithOptions creates a new OSV API client with custom options.
func NewClientWithOptions(baseURL string, ratePerSecond float64, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		limiter: rate.NewLimiter(rate.Limit(ratePerSecond), 1),
	}
}

// GetVulnerability fetches a vulnerability by ID from the OSV API with automatic retry on 429.
func (c *Client) GetVulnerability(ctx context.Context, id string) (*Vulnerability, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		vuln, err := c.getVulnerabilityOnce(ctx, id)
		if err == nil {
			return vuln, nil
		}

		// If error is not 429, return immediately
		if !errors.Is(err, ErrTooManyRequests) {
			return nil, err
		}

		// 429 error - wait before retry
		lastErr = err
		if attempt < maxRetries-1 {
			backoff := time.Duration(attempt+1) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) getVulnerabilityOnce(ctx context.Context, id string) (*Vulnerability, error) {
	// Apply rate limiting if configured
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}
	}

	url := fmt.Sprintf("%s/v1/vulns/%s", c.baseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}

	if resp.StatusCode == http.StatusBadRequest {
		return nil, ErrBadRequest
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrTooManyRequests
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &vuln, nil
}
