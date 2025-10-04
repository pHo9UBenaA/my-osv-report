package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/metrics"
)

func TestParseGitHubURL(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "valid https URL",
			url:       "https://github.com/google/osv",
			wantOwner: "google",
			wantRepo:  "osv",
			wantErr:   false,
		},
		{
			name:      "valid https URL with trailing slash",
			url:       "https://github.com/google/osv/",
			wantOwner: "google",
			wantRepo:  "osv",
			wantErr:   false,
		},
		{
			name:    "invalid URL",
			url:     "not-a-url",
			wantErr: true,
		},
		{
			name:    "non-github URL",
			url:     "https://gitlab.com/owner/repo",
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := metrics.ParseGitHubURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseGitHubURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

func TestGitHubClient_GetStars(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		expectedPath := "/repos/google/osv"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"stargazers_count": 1234}`))
	}))
	defer server.Close()

	client := metrics.NewGitHubClient(server.URL, "")
	ctx := context.Background()

	stars, err := client.GetStars(ctx, "google", "osv")
	if err != nil {
		t.Fatalf("GetStars() error = %v", err)
	}
	if stars != 1234 {
		t.Errorf("stars = %d, want 1234", stars)
	}
}
