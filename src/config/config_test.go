package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/config"
	"github.com/pHo9UBenaA/osv-scraper/src/ecosystem"
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
