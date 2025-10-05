package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/pHo9UBenaA/osv-scraper/src/ecosystem"
)

// Config holds application configuration.
type Config struct {
	APIBaseURL     string
	DBPath         string
	Ecosystems     []ecosystem.Ecosystem
	RetentionDays  int
	RateLimit      float64       // requests per second
	MaxConcurrency int           // max concurrent API requests
	BatchSize      int           // batch size for processing entries
	HTTPTimeout    time.Duration // HTTP client timeout
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

	rateLimit := 10.0 // default: 10 requests per second
	if rateLimitStr := os.Getenv("OSV_RATE_LIMIT"); rateLimitStr != "" {
		if parsed, err := strconv.ParseFloat(rateLimitStr, 64); err == nil && parsed > 0 {
			rateLimit = parsed
		}
	}

	maxConcurrency := 5 // default: 5 concurrent requests
	if maxConcStr := os.Getenv("OSV_MAX_CONCURRENCY"); maxConcStr != "" {
		if parsed, err := strconv.Atoi(maxConcStr); err == nil && parsed > 0 {
			maxConcurrency = parsed
		}
	}

	batchSize := 100 // default: 100 entries per batch
	if batchSizeStr := os.Getenv("OSV_BATCH_SIZE"); batchSizeStr != "" {
		if parsed, err := strconv.Atoi(batchSizeStr); err == nil && parsed > 0 {
			batchSize = parsed
		}
	}

	httpTimeout := 30 * time.Second // default: 30 seconds
	if timeoutStr := os.Getenv("OSV_HTTP_TIMEOUT"); timeoutStr != "" {
		if parsed, err := strconv.Atoi(timeoutStr); err == nil && parsed > 0 {
			httpTimeout = time.Duration(parsed) * time.Second
		}
	}

	cfg := &Config{
		APIBaseURL:     getEnv("OSV_API_BASE_URL", "https://api.osv.dev"),
		DBPath:         getEnv("OSV_DB_PATH", "./osv.db"),
		Ecosystems:     ecosystems,
		RetentionDays:  retentionDays,
		RateLimit:      rateLimit,
		MaxConcurrency: maxConcurrency,
		BatchSize:      batchSize,
		HTTPTimeout:    httpTimeout,
	}
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
