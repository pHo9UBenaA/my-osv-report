package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/metrics"
)

func TestPyPIClient_GetDownloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		expectedPath := "/pypi/requests/json"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"info": {"downloads": {"last_week": 9876543}}}`))
	}))
	defer server.Close()

	client := metrics.NewPyPIClient(server.URL)
	ctx := context.Background()

	downloads, err := client.GetDownloads(ctx, "requests")
	if err != nil {
		t.Fatalf("GetDownloads() error = %v", err)
	}
	if downloads != 9876543 {
		t.Errorf("downloads = %d, want 9876543", downloads)
	}
}
