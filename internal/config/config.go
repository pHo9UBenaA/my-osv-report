package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/pHo9UBenaA/osv-scraper/internal/ecosystem"
)

const (
	defaultAPIBaseURL     = "https://api.osv.dev"
	defaultDBPath         = "./osv.db"
	defaultRetentionDays  = 7
	defaultRateLimit      = 10.0 // requests per second
	defaultMaxConcurrency = 5
	defaultBatchSize      = 100
	defaultHTTPTimeout    = 30 * time.Second
)

// Config holds application configuration.
type Config struct {
	APIBaseURL     string
	DBPath         string
	Ecosystems     []ecosystem.Ecosystem
	RetentionDays  int
	RateLimit      float64
	MaxConcurrency int
	BatchSize      int
	HTTPTimeout    time.Duration
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	_ = godotenv.Load()

	ecosystems, err := ecosystem.ParseEcosystems(os.Getenv("OSV_ECOSYSTEMS"))
	if err != nil {
		return nil, err
	}

	return &Config{
		APIBaseURL:     getEnv("OSV_API_BASE_URL", defaultAPIBaseURL),
		DBPath:         getEnv("OSV_DB_PATH", defaultDBPath),
		Ecosystems:     ecosystems,
		RetentionDays:  getEnvInt("OSV_DATA_RETENTION_DAYS", defaultRetentionDays),
		RateLimit:      getEnvFloat("OSV_RATE_LIMIT", defaultRateLimit),
		MaxConcurrency: getEnvInt("OSV_MAX_CONCURRENCY", defaultMaxConcurrency),
		BatchSize:      getEnvInt("OSV_BATCH_SIZE", defaultBatchSize),
		HTTPTimeout:    getEnvDuration("OSV_HTTP_TIMEOUT", defaultHTTPTimeout),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if str := os.Getenv(key); str != "" {
		if val, err := strconv.Atoi(str); err == nil && val > 0 {
			return val
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if str := os.Getenv(key); str != "" {
		if val, err := strconv.ParseFloat(str, 64); err == nil && val > 0 {
			return val
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if str := os.Getenv(key); str != "" {
		if seconds, err := strconv.Atoi(str); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultValue
}
