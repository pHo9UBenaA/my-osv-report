package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
	"github.com/pHo9UBenaA/osv-scraper/internal/store"
)

// ReportOptions holds options for report generation.
type ReportOptions struct {
	Format    string
	Output    string
	Ecosystem string
	Diff      bool
}

// GenerateReport creates a vulnerability report from the database.
func GenerateReport(ctx context.Context, st *store.Store, opts ReportOptions) error {
	outputPath := resolveOutputPath(opts.Output, time.Now().UTC())
	slog.Info("generating report", "format", opts.Format, "output", outputPath, "ecosystem", opts.Ecosystem, "diff", opts.Diff)

	var entries []store.VulnerabilityReportEntry
	var err error

	if opts.Diff {
		entries, err = st.GetUnreportedVulnerabilities(ctx, opts.Ecosystem)
		if err != nil {
			return fmt.Errorf("get unreported vulnerabilities: %w", err)
		}
	} else {
		entries, err = st.GetVulnerabilitiesForReport(ctx, opts.Ecosystem)
		if err != nil {
			return fmt.Errorf("get vulnerabilities: %w", err)
		}
	}

	slog.Info("fetched vulnerabilities", "count", len(entries))

	if len(entries) == 0 {
		slog.Warn("no vulnerabilities found in database")
		return nil
	}

	reportEntries := convertToReportEntries(entries)
	writer := report.NewWriter()

	switch opts.Format {
	case "markdown":
		err = writer.WriteMarkdown(ctx, outputPath, reportEntries)
	case "csv":
		err = writer.WriteCSV(ctx, outputPath, reportEntries)
	case "jsonl":
		err = writer.WriteJSONL(ctx, outputPath, reportEntries)
	default:
		return fmt.Errorf("unknown report format: %s (supported: markdown, csv, jsonl)", opts.Format)
	}

	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	slog.Info("report generated successfully", "output", outputPath)

	if opts.Diff {
		allEntries, err := st.GetVulnerabilitiesForReport(ctx, opts.Ecosystem)
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

func resolveOutputPath(base string, now time.Time) string {
	if base == "" {
		return base
	}

	dir := filepath.Dir(base)
	filename := filepath.Base(base)
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(filename, ext)
	timestamp := now.Format("20060102T150405Z")

	newName := fmt.Sprintf("%s_%s%s", name, timestamp, ext)
	if dir == "." {
		return filepath.Join(dir, newName)
	}
	return filepath.Join(dir, newName)
}

func convertToReportEntries(entries []store.VulnerabilityReportEntry) []report.VulnerabilityEntry {
	result := make([]report.VulnerabilityEntry, len(entries))
	for i, e := range entries {
		var basePtr *float64
		if e.SeverityBaseScore.Valid {
			value := e.SeverityBaseScore.Float64
			basePtr = &value
		}
		result[i] = report.VulnerabilityEntry{
			ID:                e.ID,
			Ecosystem:         e.Ecosystem,
			Package:           e.Package,
			Published:         e.Published,
			Modified:          e.Modified,
			SeverityBaseScore: basePtr,
			SeverityVector:    e.SeverityVector,
		}
	}
	return result
}
