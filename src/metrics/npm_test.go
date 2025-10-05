package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestNpmClientHasTimeout(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	ctx := context.Background()
	client := metrics.NewNpmClient(server.URL)

	shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.GetDownloads(shortCtx, "express")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	if elapsed > 500*time.Millisecond {
		t.Errorf("timeout took too long: %v, client may not have timeout configured", elapsed)
	}
}
