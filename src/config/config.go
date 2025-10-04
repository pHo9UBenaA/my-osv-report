package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/pHo9UBenaA/osv-scraper/src/ecosystem"
)

// Config holds application configuration.
type Config struct {
	APIBaseURL    string
	DBPath        string
	Ecosystems    []ecosystem.Ecosystem
	RetentionDays int
}

// Load loads configuration from environment variables with defaults.
// If a .env file exists in the current directory, it will be loaded first.
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if file doesn't exist)
	_ = godotenv.Load()

	ecosystemsStr := getEnv("OSV_ECOSYSTEMS", "")
	ecosystems, err := ecosystem.ParseEcosystems(ecosystemsStr)
	if err != nil {
		return nil, err
	}

	retentionDays := 7
	if retentionStr := os.Getenv("OSV_DATA_RETENTION_DAYS"); retentionStr != "" {
		if parsed, err := strconv.Atoi(retentionStr); err == nil && parsed > 0 {
			retentionDays = parsed
		}
	}

	cfg := &Config{
		APIBaseURL:    getEnv("OSV_API_BASE_URL", "https://api.osv.dev"),
		DBPath:        getEnv("OSV_DB_PATH", "./osv.db"),
		Ecosystems:    ecosystems,
		RetentionDays: retentionDays,
	}
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
