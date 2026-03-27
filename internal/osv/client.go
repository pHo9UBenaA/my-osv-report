package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/time/rate"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

const (
	defaultHTTPClientTimeout = 30 * time.Second
	defaultRetryMax          = 2 // 3 total attempts (1 initial + 2 retries)
)

// ErrNotFound is returned when a vulnerability is not found (404).
var ErrNotFound = errors.New("not found")

// ErrBadRequest is returned when the request is invalid (400).
var ErrBadRequest = errors.New("bad request")

// ErrTooManyRequests is returned when rate limit is exceeded (429).
var ErrTooManyRequests = errors.New("too many requests")

// JSON wire types for OSV API deserialization (unexported).

type jsonPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type jsonAffected struct {
	Package jsonPackage `json:"package"`
}

type jsonSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type jsonVulnerability struct {
	ID        string         `json:"id"`
	Modified  time.Time      `json:"modified"`
	Published time.Time      `json:"published,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Details   string         `json:"details,omitempty"`
	Affected  []jsonAffected `json:"affected,omitempty"`
	Severity  []jsonSeverity `json:"severity,omitempty"`
}

func toModelVulnerability(v *jsonVulnerability) *model.Vulnerability {
	affected := make([]model.AffectedPackage, len(v.Affected))
	for i, a := range v.Affected {
		affected[i] = model.AffectedPackage{
			Ecosystem: a.Package.Ecosystem,
			Name:      a.Package.Name,
		}
	}

	severity := make([]model.SeverityEntry, len(v.Severity))
	for i, s := range v.Severity {
		severity[i] = model.SeverityEntry{
			Type:  s.Type,
			Score: s.Score,
		}
	}

	return &model.Vulnerability{
		ID:        v.ID,
		Modified:  v.Modified,
		Published: v.Published,
		Summary:   v.Summary,
		Details:   v.Details,
		Affected:  affected,
		Severity:  severity,
	}
}

// rateLimitedTransport wraps an http.RoundTripper with rate limiting.
// This ensures rate limiting is applied to every HTTP request including retries.
type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limiter != nil {
		if err := t.limiter.Wait(req.Context()); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}
	}
	return t.base.RoundTrip(req)
}

// Client is an HTTP client for the OSV API.
type Client struct {
	baseURL     string
	retryClient *retryablehttp.Client
	transport   *rateLimitedTransport
}

type limiter interface {
	Wait(context.Context) error
}

type limiterFunc func(context.Context) error

func (f limiterFunc) Wait(ctx context.Context) error {
	if f == nil {
		return nil
	}
	return f(ctx)
}

// ClientOption configures optional client behaviour.
type ClientOption func(*Client)

// WithLimiterWaitFunc sets a custom limiter wait function.
func WithLimiterWaitFunc(wait func(context.Context) error) ClientOption {
	return func(c *Client) {
		if wait == nil {
			c.transport.limiter = nil
			return
		}
		c.transport.limiter = limiterFunc(wait)
	}
}

// WithBackoff sets a custom backoff strategy for retries.
// The function receives the attempt number (0-based) and the HTTP response,
// and returns the duration to wait before the next retry.
func WithBackoff(fn func(attemptNum int, resp *http.Response) time.Duration) ClientOption {
	return func(c *Client) {
		if fn == nil {
			return
		}
		c.retryClient.Backoff = func(_, _ time.Duration, attemptNum int, resp *http.Response) time.Duration {
			return fn(attemptNum, resp)
		}
	}
}

// checkRetryPolicy retries on HTTP 429 and transient network errors.
// Timeouts are not retried to avoid excessive delays.
func checkRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return false, err
		}
		return true, nil
	}
	return resp.StatusCode == http.StatusTooManyRequests, nil
}

func newClient(baseURL string, timeout time.Duration, lim limiter, opts ...ClientOption) *Client {
	transport := &rateLimitedTransport{
		base:    http.DefaultTransport,
		limiter: lim,
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = defaultRetryMax
	rc.RetryWaitMin = 1 * time.Second
	rc.RetryWaitMax = 30 * time.Second
	rc.Logger = nil
	rc.CheckRetry = checkRetryPolicy
	rc.ErrorHandler = retryablehttp.PassthroughErrorHandler
	rc.HTTPClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	c := &Client{
		baseURL:     baseURL,
		retryClient: rc,
		transport:   transport,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	return c
}

// NewClient creates a new OSV API client without rate limiting.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	return newClient(baseURL, defaultHTTPClientTimeout, nil, opts...)
}

// NewClientWithRateLimit creates a new OSV API client with rate limiting.
// ratePerSecond specifies the maximum number of requests per second.
func NewClientWithRateLimit(baseURL string, ratePerSecond float64, opts ...ClientOption) *Client {
	lim := rate.NewLimiter(rate.Limit(ratePerSecond), 1)
	return newClient(baseURL, defaultHTTPClientTimeout, lim, opts...)
}

// NewClientWithOptions creates a new OSV API client with custom options.
func NewClientWithOptions(baseURL string, ratePerSecond float64, timeout time.Duration, opts ...ClientOption) *Client {
	lim := rate.NewLimiter(rate.Limit(ratePerSecond), 1)
	return newClient(baseURL, timeout, lim, opts...)
}

// GetVulnerability fetches a vulnerability by ID from the OSV API.
// Retries automatically on HTTP 429 and transient network errors
// using exponential backoff with Retry-After support.
// Rate limiting is applied per-request at the transport level,
// including retry attempts.
func (c *Client) GetVulnerability(ctx context.Context, id string) (*model.Vulnerability, error) {
	reqURL := fmt.Sprintf("%s/v1/vulns/%s", c.baseURL, id)

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.retryClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue to decode
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusBadRequest:
		return nil, ErrBadRequest
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("max retries exceeded: %w", ErrTooManyRequests)
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var vuln jsonVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return toModelVulnerability(&vuln), nil
}
