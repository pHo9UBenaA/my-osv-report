package osv_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/osv"
)

func TestGetVulnerability(t *testing.T) {
	cases := []struct {
		name        string
		id          string
		serverResp  string
		statusCode  int
		wantErr     bool
		wantErrType error
	}{
		{
			name: "successful request",
			id:   "GHSA-xxxx-yyyy-zzzz",
			serverResp: `{
				"id": "GHSA-xxxx-yyyy-zzzz",
				"modified": "2025-10-04T12:34:56Z"
			}`,
			statusCode:  http.StatusOK,
			wantErr:     false,
			wantErrType: nil,
		},
		{
			name: "parse detailed vulnerability",
			id:   "GHSA-detail-test",
			serverResp: `{
				"id": "GHSA-detail-test",
				"modified": "2025-10-04T12:34:56Z",
				"summary": "Test vulnerability",
				"details": "Detailed description",
				"affected": [
					{
						"package": {"ecosystem": "Go", "name": "github.com/test/pkg"},
						"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
					}
				],
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
				],
				"references": [
					{"type": "ADVISORY", "url": "https://example.com/advisory"}
				]
			}`,
			statusCode:  http.StatusOK,
			wantErr:     false,
			wantErrType: nil,
		},
		{
			name:        "not found returns ErrNotFound",
			id:          "GHSA-0000-0000-0000",
			serverResp:  "",
			statusCode:  http.StatusNotFound,
			wantErr:     true,
			wantErrType: osv.ErrNotFound,
		},
		{
			name:        "bad request returns ErrBadRequest",
			id:          "invalid-id",
			serverResp:  "",
			statusCode:  http.StatusBadRequest,
			wantErr:     true,
			wantErrType: osv.ErrBadRequest,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				expectedPath := "/v1/vulns/" + tt.id
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.serverResp))
			}))
			defer server.Close()

			client := osv.NewClient(server.URL)
			ctx := context.Background()
			vuln, err := client.GetVulnerability(ctx, tt.id)

			if (err != nil) != tt.wantErr {
				t.Fatalf("GetVulnerability() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("error type = %v, want %v", err, tt.wantErrType)
				}
				return
			}
			if vuln.ID != tt.id {
				t.Errorf("vuln.ID = %q, want %q", vuln.ID, tt.id)
			}

			// Additional checks for detailed test case
			if tt.name == "parse detailed vulnerability" {
				if vuln.Summary != "Test vulnerability" {
					t.Errorf("vuln.Summary = %q, want %q", vuln.Summary, "Test vulnerability")
				}
				if len(vuln.Affected) != 1 {
					t.Errorf("len(vuln.Affected) = %d, want 1", len(vuln.Affected))
				}
				if len(vuln.Severity) != 1 {
					t.Errorf("len(vuln.Severity) = %d, want 1", len(vuln.Severity))
				}
				if len(vuln.References) != 1 {
					t.Errorf("len(vuln.References) = %d, want 1", len(vuln.References))
				}
			}
		})
	}
}

func TestClientWithRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`))
	}))
	defer server.Close()

	// Create client with 2 requests per second rate limit
	client := osv.NewClientWithRateLimit(server.URL, 2.0)
	ctx := context.Background()

	// Make 5 requests - should take at least 2 seconds with 2 req/s limit
	start := time.Now()
	for i := 0; i < 5; i++ {
		_, err := client.GetVulnerability(ctx, "test")
		if err != nil {
			t.Fatalf("GetVulnerability() error = %v", err)
		}
	}
	elapsed := time.Since(start)

	// With 2 req/s: 5 requests should take at least 2 seconds
	// (0s, 0.5s, 1s, 1.5s, 2s)
	if elapsed < 2*time.Second {
		t.Errorf("rate limit not working: elapsed %v, expected >= 2s", elapsed)
	}
}

func TestGetVulnerability429Retry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			// Return 429 for first 2 calls
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// Return success on 3rd call
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`))
	}))
	defer server.Close()

	client := osv.NewClient(server.URL)
	ctx := context.Background()

	vuln, err := client.GetVulnerability(ctx, "test")
	if err != nil {
		t.Fatalf("GetVulnerability() error = %v, want success after retries", err)
	}
	if vuln.ID != "test" {
		t.Errorf("vuln.ID = %q, want %q", vuln.ID, "test")
	}
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3 (should retry on 429)", callCount)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`))
	}))
	defer server.Close()

	// Create client with custom timeout and rate limit
	client := osv.NewClientWithOptions(server.URL, 10.0, 200*time.Millisecond)
	ctx := context.Background()

	// Should succeed with 200ms timeout (server responds in 100ms)
	_, err := client.GetVulnerability(ctx, "test")
	if err != nil {
		t.Fatalf("GetVulnerability() error = %v", err)
	}

	// Test with very short timeout
	clientShortTimeout := osv.NewClientWithOptions(server.URL, 10.0, 50*time.Millisecond)
	_, err = clientShortTimeout.GetVulnerability(ctx, "test")
	if err == nil {
		t.Error("expected timeout error with 50ms timeout and 100ms response time")
	}
}
