package fetcher_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/fetcher"
)

func TestFetchCSV(t *testing.T) {
	csvContent := `GHSA-0001,2025-10-04T10:00:00Z
GHSA-0002,2025-10-04T11:00:00Z`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(csvContent))
	}))
	defer server.Close()

	ctx := context.Background()
	f := fetcher.NewCSVFetcher(server.URL)

	entries, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("len(entries) = %d, want 2", len(entries))
	}

	if entries[0].ID != "GHSA-0001" {
		t.Errorf("entries[0].ID = %q, want %q", entries[0].ID, "GHSA-0001")
	}
}

func TestCSVFetcherHasTimeout(t *testing.T) {
	// Create a server that delays longer than reasonable timeout
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	ctx := context.Background()
	f := fetcher.NewCSVFetcher(server.URL)

	// Set a very short context timeout to verify client respects deadlines
	shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := f.Fetch(shortCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	// Should timeout quickly (within context deadline), not wait indefinitely
	if elapsed > 500*time.Millisecond {
		t.Errorf("timeout took too long: %v, client may not have timeout configured", elapsed)
	}
}
