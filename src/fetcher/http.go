package fetcher

import (
	"net/http"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// NewHTTPClient creates a new HTTP client with default timeout.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
	}
}

// NewHTTPClientWithTimeout creates a new HTTP client with custom timeout.
func NewHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}
