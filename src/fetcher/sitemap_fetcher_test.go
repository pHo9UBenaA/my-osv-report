package fetcher_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/fetcher"
)

func TestNewSitemapFetcher(t *testing.T) {
	url := "https://osv.dev/sitemap_npm.xml"
	f := fetcher.NewSitemapFetcher(url)
	if f == nil {
		t.Fatal("NewSitemapFetcher() returned nil")
	}
}

func TestSitemapFetcher_Fetch(t *testing.T) {
	// Mock sitemap XML response
	mockXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz</loc>
		<lastmod>2025-10-03T21:48:36+00:00</lastmod>
	</url>
	<url>
		<loc>https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc</loc>
		<lastmod>2025-10-02T15:30:00+00:00</lastmod>
	</url>
	<url>
		<loc>https://osv.dev/vulnerability/MAL-2025-12345</loc>
		<lastmod>2025-10-01T10:00:00+00:00</lastmod>
	</url>
</urlset>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockXML))
	}))
	defer server.Close()

	f := fetcher.NewSitemapFetcher(server.URL)
	ctx := context.Background()

	entries, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Fetch() returned %d entries, want 3", len(entries))
	}

	// Verify first entry
	if entries[0].ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("entries[0].ID = %q, want %q", entries[0].ID, "GHSA-xxxx-yyyy-zzzz")
	}

	expectedTime := time.Date(2025, 10, 3, 21, 48, 36, 0, time.UTC)
	if !entries[0].Modified.Equal(expectedTime) {
		t.Errorf("entries[0].Modified = %v, want %v", entries[0].Modified, expectedTime)
	}

	// Verify second entry
	if entries[1].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("entries[1].ID = %q, want %q", entries[1].ID, "GHSA-aaaa-bbbb-cccc")
	}

	// Verify third entry (MAL- prefix)
	if entries[2].ID != "MAL-2025-12345" {
		t.Errorf("entries[2].ID = %q, want %q", entries[2].ID, "MAL-2025-12345")
	}
}

func TestSitemapFetcher_FetchWithCursorFilter(t *testing.T) {
	// Mock sitemap XML response with various dates
	mockXML := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>https://osv.dev/vulnerability/GHSA-new1</loc>
		<lastmod>2025-10-05T12:00:00+00:00</lastmod>
	</url>
	<url>
		<loc>https://osv.dev/vulnerability/GHSA-old1</loc>
		<lastmod>2025-10-01T12:00:00+00:00</lastmod>
	</url>
	<url>
		<loc>https://osv.dev/vulnerability/GHSA-new2</loc>
		<lastmod>2025-10-04T12:00:00+00:00</lastmod>
	</url>
</urlset>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockXML))
	}))
	defer server.Close()

	cursor := time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC)
	f := fetcher.NewSitemapFetcherWithCursor(server.URL, cursor)
	ctx := context.Background()

	entries, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	// Should only return entries after 2025-10-03
	if len(entries) != 2 {
		t.Errorf("Fetch() returned %d entries, want 2", len(entries))
	}

	// Verify filtered entries
	if entries[0].ID != "GHSA-new1" {
		t.Errorf("entries[0].ID = %q, want %q", entries[0].ID, "GHSA-new1")
	}

	if entries[1].ID != "GHSA-new2" {
		t.Errorf("entries[1].ID = %q, want %q", entries[1].ID, "GHSA-new2")
	}
}
