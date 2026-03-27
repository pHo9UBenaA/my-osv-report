package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/pHo9UBenaA/osv-scraper/internal/model"
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
	Ecosystems     []model.Ecosystem
	RetentionDays  int
	RateLimit      float64
	MaxConcurrency int
	BatchSize      int
	HTTPTimeout    time.Duration
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	_ = godotenv.Load()

	ecosystems, err := model.ParseEcosystems(os.Getenv("OSV_ECOSYSTEMS"))
	if err != nil {
		return nil, err
	}

	retentionDays, err := getEnvInt("OSV_DATA_RETENTION_DAYS", defaultRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_DATA_RETENTION_DAYS: %w", err)
	}

	rateLimit, err := getEnvFloat("OSV_RATE_LIMIT", defaultRateLimit)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_RATE_LIMIT: %w", err)
	}

	maxConcurrency, err := getEnvInt("OSV_MAX_CONCURRENCY", defaultMaxConcurrency)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_MAX_CONCURRENCY: %w", err)
	}

	batchSize, err := getEnvInt("OSV_BATCH_SIZE", defaultBatchSize)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_BATCH_SIZE: %w", err)
	}

	httpTimeout, err := getEnvDuration("OSV_HTTP_TIMEOUT", defaultHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_HTTP_TIMEOUT: %w", err)
	}

	return &Config{
		APIBaseURL:     getEnv("OSV_API_BASE_URL", defaultAPIBaseURL),
		DBPath:         getEnv("OSV_DB_PATH", defaultDBPath),
		Ecosystems:     ecosystems,
		RetentionDays:  retentionDays,
		RateLimit:      rateLimit,
		MaxConcurrency: maxConcurrency,
		BatchSize:      batchSize,
		HTTPTimeout:    httpTimeout,
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// B11: return errors from env parsing instead of silently falling back to defaults
func getEnvInt(key string, defaultValue int) (int, error) {
	str := os.Getenv(key)
	if str == "" {
		return defaultValue, nil
	}
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", str, err)
	}
	if val <= 0 {
		return 0, fmt.Errorf("value must be positive, got %d", val)
	}
	return val, nil
}

func getEnvFloat(key string, defaultValue float64) (float64, error) {
	str := os.Getenv(key)
	if str == "" {
		return defaultValue, nil
	}
	val, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid float %q: %w", str, err)
	}
	if val <= 0 {
		return 0, fmt.Errorf("value must be positive, got %f", val)
	}
	return val, nil
}

func getEnvDuration(key string, defaultValue time.Duration) (time.Duration, error) {
	str := os.Getenv(key)
	if str == "" {
		return defaultValue, nil
	}
	seconds, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", str, err)
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("value must be positive, got %d", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}
