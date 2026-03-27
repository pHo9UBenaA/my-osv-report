package osv_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/osv"
)

func TestGetVulnerability_StatusCodeHandling(t *testing.T) {
	cases := []struct {
		name        string
		id          string
		serverResp  string
		statusCode  int
		wantErr     bool
		wantErrType error
	}{
		{
			name: "ValidID_ReturnsDecodedVulnerability",
			id:   "GHSA-xxxx-yyyy-zzzz",
			serverResp: `{
				"id": "GHSA-xxxx-yyyy-zzzz",
				"modified": "2025-10-04T12:34:56Z",
				"summary": "Test vulnerability",
				"affected": [
					{
						"package": {"ecosystem": "Go", "name": "github.com/test/pkg"}
					}
				],
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
				]
			}`,
			statusCode:  http.StatusOK,
			wantErr:     false,
			wantErrType: nil,
		},
		{
			name: "DetailedResponse_DeserializesAllFields",
			id:   "GHSA-detail-test",
			serverResp: `{
				"id": "GHSA-detail-test",
				"modified": "2025-10-04T12:34:56Z",
				"summary": "Test vulnerability",
				"details": "Detailed description",
				"affected": [
					{
						"package": {"ecosystem": "Go", "name": "github.com/test/pkg"}
					}
				],
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
				]
			}`,
			statusCode:  http.StatusOK,
			wantErr:     false,
			wantErrType: nil,
		},
		{
			name:        "NonExistentID_ReturnsErrNotFound",
			id:          "GHSA-0000-0000-0000",
			serverResp:  "",
			statusCode:  http.StatusNotFound,
			wantErr:     true,
			wantErrType: osv.ErrNotFound,
		},
		{
			name:        "MalformedID_ReturnsErrBadRequest",
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
				if _, err := w.Write([]byte(tt.serverResp)); err != nil {
					t.Errorf("failed to write response: %v", err)
				}
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

			if tt.name == "DetailedResponse_DeserializesAllFields" {
				if vuln.Summary != "Test vulnerability" {
					t.Errorf("vuln.Summary = %q, want %q", vuln.Summary, "Test vulnerability")
				}
				if len(vuln.Affected) != 1 || vuln.Affected[0].Ecosystem != "Go" {
					t.Errorf("vuln.Affected = %v, want 1 entry with ecosystem Go", vuln.Affected)
				}
				if len(vuln.Severity) != 1 || vuln.Severity[0].Type != "CVSS_V3" {
					t.Errorf("vuln.Severity = %v, want 1 entry with type CVSS_V3", vuln.Severity)
				}
			}
		})
	}
}

func TestGetVulnerability_RateLimitedClient_InvokesLimiterPerRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	waits := 0
	client := osv.NewClientWithRateLimit(
		server.URL,
		2.0,
		osv.WithLimiterWaitFunc(func(ctx context.Context) error {
			waits++
			return nil
		}),
	)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := client.GetVulnerability(ctx, "test")
		if err != nil {
			t.Fatalf("GetVulnerability() error = %v", err)
		}
	}

	if waits != 5 {
		t.Fatalf("limiter wait called %d times, want 5", waits)
	}
}

func TestGetVulnerability_TransientRateLimit_RetriesAndSucceeds(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := osv.NewClient(server.URL, osv.WithBackoff(func(attemptNum int, resp *http.Response) time.Duration {
		return 0
	}))
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

func TestGetVulnerability_PersistentRateLimit_ReturnsErrTooManyRequests(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := osv.NewClient(server.URL, osv.WithBackoff(func(attemptNum int, resp *http.Response) time.Duration {
		return 0
	}))
	ctx := context.Background()

	_, err := client.GetVulnerability(ctx, "test")
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if !errors.Is(err, osv.ErrTooManyRequests) {
		t.Errorf("error = %v, want ErrTooManyRequests", err)
	}
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

func TestNewClientWithOptions_ShortTimeout_FailsFast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":"test","modified":"2025-10-04T12:00:00Z"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	clientShortTimeout := osv.NewClientWithOptions(server.URL, 10.0, 50*time.Millisecond)
	_, err := clientShortTimeout.GetVulnerability(context.Background(), "test")
	if err == nil {
		t.Error("expected timeout error with 50ms timeout and 100ms response time")
	}
}
