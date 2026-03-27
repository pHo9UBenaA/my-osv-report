package config_test

import (
	"os"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/config"
	"github.com/pHo9UBenaA/osv-scraper/internal/model"
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
