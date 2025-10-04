package fetcher_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/fetcher"
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
