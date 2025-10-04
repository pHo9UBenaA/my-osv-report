package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/metrics"
)

func TestNpmClient_GetDownloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		expectedPath := "/downloads/point/last-week/express"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"downloads": 5678901}`))
	}))
	defer server.Close()

	client := metrics.NewNpmClient(server.URL)
	ctx := context.Background()

	downloads, err := client.GetDownloads(ctx, "express")
	if err != nil {
		t.Fatalf("GetDownloads() error = %v", err)
	}
	if downloads != 5678901 {
		t.Errorf("downloads = %d, want 5678901", downloads)
	}
}
