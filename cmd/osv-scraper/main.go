package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/config"
	"github.com/pHo9UBenaA/osv-scraper/src/fetcher"
	"github.com/pHo9UBenaA/osv-scraper/src/osv"
	"github.com/pHo9UBenaA/osv-scraper/src/report"
	"github.com/pHo9UBenaA/osv-scraper/src/store"
)

var (
	fetchMode       = flag.Bool("fetch", false, "Fetch vulnerability data from OSV API")
	reportMode      = flag.Bool("report", false, "Generate report instead of scraping")
	reportFormat    = flag.String("format", "markdown", "Report format: markdown, csv, jsonl")
	reportOutput    = flag.String("output", "./report.md", "Report output base path (timestamp suffix appended before extension)")
	reportEcosystem = flag.String("ecosystem", "", "Filter report by ecosystem (empty = all)")
	reportDiff      = flag.Bool("diff", false, "Generate differential report (only new/changed vulnerabilities)")
	helpMode        = flag.Bool("help", false, "Show help message")
)

var reportNow = func() time.Time {
	return time.Now().UTC()
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	// Show help if no flags or help flag
	if *helpMode || (!*fetchMode && !*reportMode) {
		showHelp()
		return nil
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Initialize store
	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer st.Close()

	// Handle report mode
	if *reportMode {
		return generateReport(ctx, st)
	}

	// Handle fetch mode
	if *fetchMode {
		return fetchVulnerabilities(ctx, cfg, st)
	}

	return nil
}

func showHelp() {
	fmt.Println(`
WARNING: This package is a PILOT VERSION and has NOT been reviewed by contributors.
Use with caution in production environments.

OSV Scraper - Vulnerability Database Tool

USAGE:
  osv-scraper [command] [options]

COMMANDS:
  -fetch              Fetch latest vulnerability data from OSV API
  -report             Generate report from local database
  -help               Show this help message

FETCH OPTIONS:
  Environment variables:
    OSV_ECOSYSTEMS          Comma-separated list of ecosystems (npm,pypi,go,etc)
    OSV_API_BASE_URL        OSV API base URL (default: https://api.osv.dev)
    OSV_DB_PATH             Database path (default: ./osv.db)
    OSV_DATA_RETENTION_DAYS Data retention period in days (default: 7)

REPORT OPTIONS:
  -format <format>    Output format: markdown, csv, jsonl (default: markdown)
  -output <file>      Output base file path (timestamp suffix appended; default: ./report.md)
  -ecosystem <name>   Filter by ecosystem (optional)
  -diff               Generate differential report (new/changed vulnerabilities only)

EXAMPLES:
  # Fetch vulnerability data
  OSV_ECOSYSTEMS=npm,pypi osv-scraper -fetch

  # Generate markdown report (creates report_<timestamp>.md)
  osv-scraper -report -format=markdown -output=report.md

  # Generate differential CSV report for npm only
  osv-scraper -report -diff -format=csv -ecosystem=npm -output=npm-diff.csv

For more information, see: https://github.com/pHo9UBenaA/osv-scraper/
// `)
}

func fetchVulnerabilities(ctx context.Context, cfg *config.Config, st *store.Store) error {
	// Check ecosystems configuration
	if len(cfg.Ecosystems) == 0 {
		slog.Warn("no ecosystems configured, set OSV_ECOSYSTEMS environment variable")
		return nil
	}

	slog.Info("starting vulnerability fetch",
		"ecosystems", cfg.Ecosystems,
		"rateLimit", cfg.RateLimit,
		"maxConcurrency", cfg.MaxConcurrency,
		"batchSize", cfg.BatchSize)

	// Process each ecosystem
	apiClient := osv.NewClientWithOptions(cfg.APIBaseURL, cfg.RateLimit, cfg.HTTPTimeout)
	adapter := &storeAdapter{s: st}
	scraper := osv.NewScraper(apiClient, adapter)

	var lastErr error
	for _, eco := range cfg.Ecosystems {
		if err := processEcosystem(ctx, eco, st, scraper, cfg); err != nil {
			slog.Error("failed to process ecosystem", "ecosystem", eco, "error", err)
			lastErr = err
			continue
		}
	}

	if lastErr != nil {
		return fmt.Errorf("some ecosystems failed to process: %w", lastErr)
	}

	slog.Info("completed vulnerability fetch")
	return nil
}

func processEcosystem(ctx context.Context, eco interface {
	SitemapURL() string
	String() string
}, st *store.Store, scraper *osv.Scraper, cfg *config.Config) error {
	source := eco.String()
	slog.Info("processing ecosystem", "ecosystem", source)

	// Calculate retention cutoff time
	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	// Get last cursor
	lastCursor, err := st.GetCursor(ctx, source)
	if err != nil {
		// Distinguish between "no cursor found" (expected) and database errors (critical)
		if err == sql.ErrNoRows {
			lastCursor = time.Time{}
			slog.Info("no cursor found, starting from beginning", "ecosystem", source)
		} else {
			return fmt.Errorf("failed to get cursor for %s: %w", source, err)
		}
	} else {
		slog.Info("resuming from cursor", "ecosystem", source, "cursor", lastCursor)
	}

	// Fetch from sitemap with cursor filtering
	sitemapURL := eco.SitemapURL()
	sitemapFetcher := fetcher.NewSitemapFetcherWithCursor(sitemapURL, lastCursor)
	entries, err := sitemapFetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch sitemap from %s: %w", sitemapURL, err)
	}

	slog.Info("fetched entries from sitemap", "ecosystem", source, "count", len(entries))

	// Filter by retention period
	retentionFiltered := osv.FilterByCursor(entries, retentionCutoff)
	slog.Info("filtered by retention", "ecosystem", source, "count", len(retentionFiltered), "cutoff", retentionCutoff)

	if len(retentionFiltered) == 0 {
		slog.Info("no new entries to process", "ecosystem", source)
		return nil
	}

	// Process entries in batches with parallel processing
	for i := 0; i < len(retentionFiltered); i += cfg.BatchSize {
		end := i + cfg.BatchSize
		if end > len(retentionFiltered) {
			end = len(retentionFiltered)
		}

		batch := retentionFiltered[i:end]
		slog.Info("processing batch", "ecosystem", source, "batchStart", i, "batchEnd", end, "total", len(retentionFiltered))

		if err := scraper.ProcessEntriesParallel(ctx, batch, cfg.MaxConcurrency); err != nil {
			return fmt.Errorf("process batch: %w", err)
		}
	}

	// Update cursor to the latest modified time
	latestModified := retentionFiltered[len(retentionFiltered)-1].Modified
	if err := st.SaveCursor(ctx, source, latestModified); err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}

	// Delete old data from database
	if err := st.DeleteVulnerabilitiesOlderThan(ctx, retentionCutoff); err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}
	slog.Info("deleted old data", "ecosystem", source, "cutoff", retentionCutoff)

	slog.Info("completed ecosystem", "ecosystem", source, "processed", len(retentionFiltered), "cursor", latestModified)
	return nil
}

type storeAdapter struct {
	s *store.Store
}

func (a *storeAdapter) SaveVulnerability(ctx context.Context, vuln *osv.Vulnerability) error {
	baseScore, vector := extractSeverityInfo(vuln.Severity)

	var base sql.NullFloat64
	if baseScore != nil {
		base = sql.NullFloat64{Float64: *baseScore, Valid: true}
	}

	return a.s.SaveVulnerability(ctx, store.Vulnerability{
		ID:                vuln.ID,
		Modified:          vuln.Modified,
		Published:         vuln.Published,
		Summary:           vuln.Summary,
		Details:           vuln.Details,
		SeverityBaseScore: base,
		SeverityVector:    vector,
	})
}

// extractSeverityInfo extracts severity vector and base score information from OSV severity data.
// It returns the vector string (if available) and the computed base score for CVSS v3.x vectors.
func extractSeverityInfo(severities []osv.Severity) (*float64, string) {
	if len(severities) == 0 {
		return nil, ""
	}

	vector := strings.TrimSpace(severities[0].Score)
	if vector == "" {
		return nil, ""
	}

	base, err := parseSeverityScore(vector)
	if err != nil {
		slog.Debug("unsupported severity vector", "vector", vector, "err", err)
		return nil, vector
	}

	return &base, vector
}

// parseSeverityScore parses a severity score string and returns the numeric base score when possible.
func parseSeverityScore(score string) (float64, error) {
	if strings.HasPrefix(score, "CVSS:3.") {
		return computeCVSS3BaseScore(score)
	}

	return strconv.ParseFloat(score, 64)
}

// computeCVSS3BaseScore calculates the CVSS v3.x base score from a vector string.
func computeCVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid CVSS vector")
	}
	if !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("unsupported CVSS version")
	}

	metrics := make(map[string]string, len(parts)-1)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, key := range required {
		if _, ok := metrics[key]; !ok {
			return 0, fmt.Errorf("missing metric %s", key)
		}
	}

	avWeights := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acWeights := map[string]float64{"L": 0.77, "H": 0.44}
	uiWeights := map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	scopeChanged := metrics["S"] == "C"
	prWeightsUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}

	av, ok := avWeights[metrics["AV"]]
	if !ok {
		return 0, fmt.Errorf("invalid AV metric")
	}
	ac, ok := acWeights[metrics["AC"]]
	if !ok {
		return 0, fmt.Errorf("invalid AC metric")
	}
	var pr float64
	if scopeChanged {
		var okPR bool
		pr, okPR = prWeightsChanged[metrics["PR"]]
		if !okPR {
			return 0, fmt.Errorf("invalid PR metric")
		}
	} else {
		var okPR bool
		pr, okPR = prWeightsUnchanged[metrics["PR"]]
		if !okPR {
			return 0, fmt.Errorf("invalid PR metric")
		}
	}
	ui, ok := uiWeights[metrics["UI"]]
	if !ok {
		return 0, fmt.Errorf("invalid UI metric")
	}
	conf, ok := ciaWeights[metrics["C"]]
	if !ok {
		return 0, fmt.Errorf("invalid C metric")
	}
	integ, ok := ciaWeights[metrics["I"]]
	if !ok {
		return 0, fmt.Errorf("invalid I metric")
	}
	avail, ok := ciaWeights[metrics["A"]]
	if !ok {
		return 0, fmt.Errorf("invalid A metric")
	}

	exploitability := 8.22 * av * ac * pr * ui
	impactSubscore := 1 - (1-conf)*(1-integ)*(1-avail)
	if impactSubscore <= 0 {
		return 0, nil
	}

	var impact float64
	if scopeChanged {
		impact = 7.52*(impactSubscore-0.029) - 3.25*math.Pow(impactSubscore-0.02, 15)
		impact = math.Max(impact, 0)
		base := roundUp1Decimal(math.Min(1.08*(impact+exploitability), 10))
		return base, nil
	}

	impact = 6.42 * impactSubscore
	base := roundUp1Decimal(math.Min(impact+exploitability, 10))
	return base, nil
}

func roundUp1Decimal(val float64) float64 {
	return math.Ceil(val*10) / 10
}

func resolveReportOutputPath(base string, now time.Time) string {
	if base == "" {
		return base
	}

	dir := filepath.Dir(base)
	filename := filepath.Base(base)
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(filename, ext)
	timestamp := now.UTC().Format("20060102T150405Z")

	newName := fmt.Sprintf("%s_%s%s", name, timestamp, ext)
	if dir == "." {
		return filepath.Join(dir, newName)
	}
	return filepath.Join(dir, newName)
}

func (a *storeAdapter) SaveAffected(ctx context.Context, vulnID, ecosystem, pkg string) error {
	return a.s.SaveAffected(ctx, store.Affected{
		VulnID:    vulnID,
		Ecosystem: ecosystem,
		Package:   pkg,
	})
}

func (a *storeAdapter) SaveTombstone(ctx context.Context, id string) error {
	return a.s.SaveTombstone(ctx, id)
}

func generateReport(ctx context.Context, st *store.Store) error {
	outputPath := resolveReportOutputPath(*reportOutput, reportNow())
	slog.Info("generating report", "format", *reportFormat, "output", outputPath, "ecosystem", *reportEcosystem, "diff", *reportDiff)

	// Fetch vulnerabilities from database
	var entries []store.VulnerabilityReportEntry
	var err error

	if *reportDiff {
		// Differential mode: only fetch unreported vulnerabilities
		entries, err = st.GetUnreportedVulnerabilities(ctx, *reportEcosystem)
		if err != nil {
			return fmt.Errorf("get unreported vulnerabilities: %w", err)
		}
	} else {
		// Normal mode: fetch all vulnerabilities
		entries, err = st.GetVulnerabilitiesForReport(ctx, *reportEcosystem)
		if err != nil {
			return fmt.Errorf("get vulnerabilities: %w", err)
		}
	}

	slog.Info("fetched vulnerabilities", "count", len(entries))

	if len(entries) == 0 {
		slog.Warn("no vulnerabilities found in database")
		return nil
	}

	// Convert to report entries
	reportEntries := make([]report.VulnerabilityEntry, len(entries))
	for i, e := range entries {
		var basePtr *float64
		if e.SeverityBaseScore.Valid {
			value := e.SeverityBaseScore.Float64
			basePtr = &value
		}
		reportEntries[i] = report.VulnerabilityEntry{
			ID:                e.ID,
			Ecosystem:         e.Ecosystem,
			Package:           e.Package,
			Published:         e.Published,
			Modified:          e.Modified,
			SeverityBaseScore: basePtr,
			SeverityVector:    e.SeverityVector,
		}
	}

	// Generate report
	writer := report.NewWriter()

	switch *reportFormat {
	case "markdown":
		if err := writer.WriteMarkdown(ctx, outputPath, reportEntries); err != nil {
			return fmt.Errorf("write markdown: %w", err)
		}
	case "csv":
		if err := writer.WriteCSV(ctx, outputPath, reportEntries); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
	case "jsonl":
		if err := writer.WriteJSONL(ctx, outputPath, reportEntries); err != nil {
			return fmt.Errorf("write jsonl: %w", err)
		}
	default:
		return fmt.Errorf("unknown report format: %s (supported: markdown, csv, jsonl)", *reportFormat)
	}

	slog.Info("report generated successfully", "output", outputPath)

	// If differential mode, save snapshot of all current vulnerabilities
	if *reportDiff {
		// Fetch ALL current vulnerabilities to save as snapshot
		allEntries, err := st.GetVulnerabilitiesForReport(ctx, *reportEcosystem)
		if err != nil {
			return fmt.Errorf("get all vulnerabilities for snapshot: %w", err)
		}
		if err := st.SaveReportSnapshot(ctx, allEntries); err != nil {
			return fmt.Errorf("save report snapshot: %w", err)
		}
		slog.Info("saved report snapshot", "count", len(allEntries))
	}

	return nil
}
