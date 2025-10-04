package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/osv"
	"github.com/pHo9UBenaA/osv-scraper/src/store"
)

type storeAdapter struct {
	s *store.Store
}

func (a *storeAdapter) SaveVulnerability(ctx context.Context, vuln *osv.Vulnerability) error {
	severity := ""
	if len(vuln.Severity) > 0 {
		severity = vuln.Severity[0].Score
	}

	return a.s.SaveVulnerability(ctx, store.Vulnerability{
		ID:        vuln.ID,
		Modified:  vuln.Modified,
		Published: vuln.Published,
		Summary:   vuln.Summary,
		Details:   vuln.Details,
		Severity:  severity,
	})
}

func (a *storeAdapter) SaveAffected(ctx context.Context, vulnID, ecosystem, pkg string) error {
	return a.s.SaveAffected(ctx, store.Affected{
		VulnID:    vulnID,
		Ecosystem: ecosystem,
		Package:   pkg,
	})
}

func (a *storeAdapter) SaveTombstone(ctx context.Context, id string) error {
	return a.s.SaveTombstone(ctx, id)
}

func TestProcessEntries(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer st.Close()

	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "GHSA-found") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"GHSA-found","modified":"2025-10-04T12:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"test-package"}}]}`))
		} else if strings.Contains(r.URL.Path, "GHSA-deleted") {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := osv.NewClient(server.URL)
	adapter := &storeAdapter{s: st}
	scraper := osv.NewScraper(client, adapter)

	entries := []osv.Entry{
		{ID: "GHSA-found", Modified: time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)},
		{ID: "GHSA-deleted", Modified: time.Date(2025, 10, 4, 11, 0, 0, 0, time.UTC)},
	}

	if err := scraper.ProcessEntries(ctx, entries); err != nil {
		t.Fatalf("ProcessEntries() error = %v", err)
	}
}

func TestProcessEntriesParallel(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer st.Close()

	// Setup test server that simulates slow API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		w.Write([]byte(`{"id":"` + id + `","modified":"2025-10-04T12:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"test-package"}}]}`))
	}))
	defer server.Close()

	client := osv.NewClient(server.URL)
	adapter := &storeAdapter{s: st}
	scraper := osv.NewScraper(client, adapter)

	// Create 10 entries to test parallel processing
	entries := make([]osv.Entry, 10)
	for i := 0; i < 10; i++ {
		entries[i] = osv.Entry{
			ID:       "GHSA-test-" + strings.Repeat("x", i+1),
			Modified: time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
		}
	}

	start := time.Now()
	if err := scraper.ProcessEntriesParallel(ctx, entries, 5); err != nil {
		t.Fatalf("ProcessEntriesParallel() error = %v", err)
	}
	elapsed := time.Since(start)

	// If sequential: 10 * 100ms = 1000ms
	// If parallel (5 workers): 2 batches * 100ms = ~200ms
	if elapsed > 500*time.Millisecond {
		t.Errorf("ProcessEntriesParallel() took %v, expected < 500ms (parallel processing)", elapsed)
	}
}
