package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/config"
	"github.com/pHo9UBenaA/osv-report/internal/model"
)

func TestLoad_AllEnvVarsSet_ReturnsPopulatedConfig(t *testing.T) {
	os.Setenv("OSV_ECOSYSTEMS", "npm,PyPI,Go")
	os.Setenv("OSV_DB_PATH", "./test.db")
	os.Setenv("OSV_DATA_RETENTION_DAYS", "14")
	defer os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.DBPath != "./test.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "./test.db")
	}

	want := []model.Ecosystem{model.NPM, model.PyPI, model.Go}
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

func TestLoad_NoEnvVars_ReturnsDefaults(t *testing.T) {
	os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
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

func TestLoad_NonNumericRetentionDays_ReturnsError(t *testing.T) {
	os.Clearenv()
	os.Setenv("OSV_DATA_RETENTION_DAYS", "abc")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() should return error for invalid retention days")
	}
}

func TestLoad_DotEnvFile_LoadsConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	envContent := `OSV_ECOSYSTEMS=npm,Go
OSV_DB_PATH=./dotenv.db
OSV_DATA_RETENTION_DAYS=30`

	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("Failed to create .env file: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Errorf("Failed to restore directory: %v", err)
		}
	}()

	os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.DBPath != "./dotenv.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "./dotenv.db")
	}

	want := []model.Ecosystem{model.NPM, model.Go}
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
