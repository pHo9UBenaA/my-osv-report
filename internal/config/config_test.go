package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/config"
	"github.com/pHo9UBenaA/osv-scraper/internal/ecosystem"
)

func TestLoad(t *testing.T) {
	// Set environment variables for test
	os.Setenv("OSV_API_BASE_URL", "https://api.osv.dev")
	os.Setenv("OSV_ECOSYSTEMS", "npm,PyPI,Go")
	os.Setenv("OSV_DB_PATH", "./test.db")
	os.Setenv("OSV_DATA_RETENTION_DAYS", "14")
	defer os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIBaseURL != "https://api.osv.dev" {
		t.Errorf("APIBaseURL = %q, want %q", cfg.APIBaseURL, "https://api.osv.dev")
	}

	if cfg.DBPath != "./test.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "./test.db")
	}

	want := []ecosystem.Ecosystem{ecosystem.NPM, ecosystem.PyPI, ecosystem.Go}
	if len(cfg.Ecosystems) != len(want) {
		t.Fatalf("Ecosystems length = %d, want %d", len(cfg.Ecosystems), len(want))
	}
	for i, eco := range cfg.Ecosystems {
		if eco != want[i] {
			t.Errorf("Ecosystems[%d] = %v, want %v", i, eco, want[i])
		}
	}

	if cfg.RetentionDays != 14 {
		t.Errorf("RetentionDays = %d, want 14", cfg.RetentionDays)
	}
}

func TestLoadPerformanceSettings(t *testing.T) {
	// Set environment variables for test
	os.Setenv("OSV_RATE_LIMIT", "20.5")
	os.Setenv("OSV_MAX_CONCURRENCY", "10")
	os.Setenv("OSV_BATCH_SIZE", "200")
	os.Setenv("OSV_HTTP_TIMEOUT", "60")
	defer os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.RateLimit != 20.5 {
		t.Errorf("RateLimit = %f, want 20.5", cfg.RateLimit)
	}

	if cfg.MaxConcurrency != 10 {
		t.Errorf("MaxConcurrency = %d, want 10", cfg.MaxConcurrency)
	}

	if cfg.BatchSize != 200 {
		t.Errorf("BatchSize = %d, want 200", cfg.BatchSize)
	}

	if cfg.HTTPTimeout != 60*time.Second {
		t.Errorf("HTTPTimeout = %v, want 60s", cfg.HTTPTimeout)
	}
}

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIBaseURL == "" {
		t.Error("APIBaseURL should have a default value")
	}

	if cfg.DBPath == "" {
		t.Error("DBPath should have a default value")
	}

	if len(cfg.Ecosystems) != 0 {
		t.Errorf("Ecosystems should be empty by default, got %v", cfg.Ecosystems)
	}

	if cfg.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7 (default)", cfg.RetentionDays)
	}

	// Check performance defaults
	if cfg.RateLimit != 10.0 {
		t.Errorf("RateLimit = %f, want 10.0 (default)", cfg.RateLimit)
	}

	if cfg.MaxConcurrency != 5 {
		t.Errorf("MaxConcurrency = %d, want 5 (default)", cfg.MaxConcurrency)
	}

	if cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100 (default)", cfg.BatchSize)
	}

	if cfg.HTTPTimeout != 30*time.Second {
		t.Errorf("HTTPTimeout = %v, want 30s (default)", cfg.HTTPTimeout)
	}
}

func TestLoadFromDotEnv(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create .env file
	envContent := `OSV_API_BASE_URL=https://test.osv.dev
OSV_ECOSYSTEMS=npm,Go
OSV_DB_PATH=./dotenv.db
OSV_DATA_RETENTION_DAYS=30`

	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("Failed to create .env file: %v", err)
	}

	// Change to temp directory
	origDir, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(origDir)

	// Clear environment variables
	os.Clearenv()

	// Load config
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify values from .env file
	if cfg.APIBaseURL != "https://test.osv.dev" {
		t.Errorf("APIBaseURL = %q, want %q", cfg.APIBaseURL, "https://test.osv.dev")
	}

	if cfg.DBPath != "./dotenv.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "./dotenv.db")
	}

	want := []ecosystem.Ecosystem{ecosystem.NPM, ecosystem.Go}
	if len(cfg.Ecosystems) != len(want) {
		t.Fatalf("Ecosystems length = %d, want %d", len(cfg.Ecosystems), len(want))
	}
	for i, eco := range cfg.Ecosystems {
		if eco != want[i] {
			t.Errorf("Ecosystems[%d] = %v, want %v", i, eco, want[i])
		}
	}

	if cfg.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30", cfg.RetentionDays)
	}
}
