package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/store"
)

func TestGenerateReport_UsesTimestampedFilename(t *testing.T) {
	fixedTime := time.Date(2025, 1, 1, 9, 0, 0, 0, time.UTC)

	prevReportNow := reportNow
	reportNow = func() time.Time {
		return fixedTime
	}
	defer func() { reportNow = prevReportNow }()

	ctx := context.Background()
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")
	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer st.Close()

	vuln := store.Vulnerability{
		ID:        "GHSA-test-1234",
		Modified:  fixedTime,
		Published: fixedTime,
		Summary:   "test summary",
		Details:   "test details",
		Severity:  "HIGH",
	}

	if err := st.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	affected := store.Affected{
		VulnID:    vuln.ID,
		Ecosystem: "npm",
		Package:   "test-pkg",
	}

	if err := st.SaveAffected(ctx, affected); err != nil {
		t.Fatalf("SaveAffected() error = %v", err)
	}

	prevFormat := *reportFormat
	prevOutput := *reportOutput
	prevEcosystem := *reportEcosystem
	prevDiff := *reportDiff

	*reportFormat = "markdown"
	*reportOutput = filepath.Join(tmpDir, "report.md")
	*reportEcosystem = ""
	*reportDiff = false

	defer func() {
		*reportFormat = prevFormat
		*reportOutput = prevOutput
		*reportEcosystem = prevEcosystem
		*reportDiff = prevDiff
	}()

	if err := generateReport(ctx, st); err != nil {
		t.Fatalf("generateReport() error = %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "report_20250101T090000Z.md")
	if _, err := os.Stat(expectedPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("timestamped report not found at %s", expectedPath)
		}
		t.Fatalf("failed to stat expected report: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "report.md")); err == nil {
		t.Fatalf("unexpected file created at original output path %s", filepath.Join(tmpDir, "report.md"))
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed to stat original output path: %v", err)
	}
}
