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

func TestGenerateReport_DifferentialMode(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer st.Close()

	// Setup: Create initial vulnerabilities
	vuln1 := store.Vulnerability{
		ID:        "GHSA-initial-1",
		Modified:  time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Severity:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := st.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(vuln1) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-initial-1", Ecosystem: "npm", Package: "pkg1"}); err != nil {
		t.Fatalf("SaveAffected(vuln1) error = %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:        "GHSA-initial-2",
		Modified:  time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Severity:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := st.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(vuln2) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-initial-2", Ecosystem: "npm", Package: "pkg2"}); err != nil {
		t.Fatalf("SaveAffected(vuln2) error = %v", err)
	}

	// Configure flags for first differential report
	prevFormat := *reportFormat
	prevOutput := *reportOutput
	prevEcosystem := *reportEcosystem
	prevDiff := *reportDiff
	defer func() {
		*reportFormat = prevFormat
		*reportOutput = prevOutput
		*reportEcosystem = prevEcosystem
		*reportDiff = prevDiff
	}()

	*reportFormat = "jsonl"
	*reportOutput = filepath.Join(tmpDir, "report.jsonl")
	*reportEcosystem = ""
	*reportDiff = true

	// First run: Generate differential report
	if err := generateReport(ctx, st); err != nil {
		t.Fatalf("generateReport() first run error = %v", err)
	}

	// Verify: Snapshot should contain ALL current vulnerabilities
	allEntries, err := st.GetVulnerabilitiesWithMetrics(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics() error = %v", err)
	}
	if len(allEntries) != 2 {
		t.Fatalf("Expected 2 vulnerabilities in DB, got %d", len(allEntries))
	}

	// Check snapshot directly
	unreportedAfterFirst, err := st.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() after first run error = %v", err)
	}
	if len(unreportedAfterFirst) != 0 {
		t.Errorf("After first run, expected 0 unreported vulnerabilities, got %d", len(unreportedAfterFirst))
	}

	// Add new vulnerability
	vuln3 := store.Vulnerability{
		ID:        "GHSA-new-3",
		Modified:  time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Severity:  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
	}
	if err := st.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(vuln3) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-new-3", Ecosystem: "npm", Package: "pkg3"}); err != nil {
		t.Fatalf("SaveAffected(vuln3) error = %v", err)
	}

	// Second run: Generate differential report again
	*reportOutput = filepath.Join(tmpDir, "report2.jsonl")
	if err := generateReport(ctx, st); err != nil {
		t.Fatalf("generateReport() second run error = %v", err)
	}

	// After second run, GetUnreportedVulnerabilities should return 0 because snapshot was updated
	finalUnreported, err := st.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() after second run error = %v", err)
	}
	if len(finalUnreported) != 0 {
		t.Errorf("After second run, expected 0 unreported vulnerabilities, got %d", len(finalUnreported))
	}

	// Verify: Snapshot should now contain all 3 vulnerabilities
	allEntriesAfter, err := st.GetVulnerabilitiesWithMetrics(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics() after second run error = %v", err)
	}
	if len(allEntriesAfter) != 3 {
		t.Fatalf("Expected 3 vulnerabilities in DB after second run, got %d", len(allEntriesAfter))
	}
}

func TestGenerateReport_DifferentialModeWithEcosystemFilter(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer st.Close()

	// Setup: Create vulnerabilities in different ecosystems
	npmVuln := store.Vulnerability{
		ID:        "GHSA-npm-1",
		Modified:  time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Severity:  "HIGH",
	}
	if err := st.SaveVulnerability(ctx, npmVuln); err != nil {
		t.Fatalf("SaveVulnerability(npmVuln) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-npm-1", Ecosystem: "npm", Package: "npm-pkg"}); err != nil {
		t.Fatalf("SaveAffected(npmVuln) error = %v", err)
	}

	pypiVuln := store.Vulnerability{
		ID:        "GHSA-pypi-1",
		Modified:  time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Severity:  "MEDIUM",
	}
	if err := st.SaveVulnerability(ctx, pypiVuln); err != nil {
		t.Fatalf("SaveVulnerability(pypiVuln) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-pypi-1", Ecosystem: "PyPI", Package: "pypi-pkg"}); err != nil {
		t.Fatalf("SaveAffected(pypiVuln) error = %v", err)
	}

	// Configure flags for npm-only differential report
	prevFormat := *reportFormat
	prevOutput := *reportOutput
	prevEcosystem := *reportEcosystem
	prevDiff := *reportDiff
	defer func() {
		*reportFormat = prevFormat
		*reportOutput = prevOutput
		*reportEcosystem = prevEcosystem
		*reportDiff = prevDiff
	}()

	*reportFormat = "jsonl"
	*reportOutput = filepath.Join(tmpDir, "npm-report.jsonl")
	*reportEcosystem = "npm"
	*reportDiff = true

	// Generate differential report for npm only
	if err := generateReport(ctx, st); err != nil {
		t.Fatalf("generateReport() npm-only error = %v", err)
	}

	// Verify: Only npm vulnerability should be in snapshot
	npmUnreported, err := st.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm) error = %v", err)
	}
	if len(npmUnreported) != 0 {
		t.Errorf("After npm report, expected 0 unreported npm vulnerabilities, got %d", len(npmUnreported))
	}

	// PyPI vulnerability should still be unreported for PyPI ecosystem
	pypiUnreported, err := st.GetUnreportedVulnerabilities(ctx, "PyPI")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(PyPI) error = %v", err)
	}
	if len(pypiUnreported) != 1 {
		t.Errorf("PyPI vulnerabilities should remain unreported after npm-only report, got %d unreported", len(pypiUnreported))
	}

	// Add new npm vulnerability
	newNpmVuln := store.Vulnerability{
		ID:        "GHSA-npm-2",
		Modified:  time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Severity:  "LOW",
	}
	if err := st.SaveVulnerability(ctx, newNpmVuln); err != nil {
		t.Fatalf("SaveVulnerability(newNpmVuln) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-npm-2", Ecosystem: "npm", Package: "npm-pkg2"}); err != nil {
		t.Fatalf("SaveAffected(newNpmVuln) error = %v", err)
	}

	// Second run: Should only report the new npm vulnerability
	*reportOutput = filepath.Join(tmpDir, "npm-report2.jsonl")
	if err := generateReport(ctx, st); err != nil {
		t.Fatalf("generateReport() second npm run error = %v", err)
	}

	// Verify: No unreported npm vulnerabilities after second run
	npmUnreportedAfter, err := st.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm) after second run error = %v", err)
	}
	if len(npmUnreportedAfter) != 0 {
		t.Errorf("After second npm report, expected 0 unreported npm vulnerabilities, got %d", len(npmUnreportedAfter))
	}

	// PyPI should still have one unreported
	pypiUnreportedAfter, err := st.GetUnreportedVulnerabilities(ctx, "PyPI")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(PyPI) after second npm run error = %v", err)
	}
	if len(pypiUnreportedAfter) != 1 {
		t.Errorf("PyPI vulnerabilities should still have 1 unreported after npm reports, got %d", len(pypiUnreportedAfter))
	}
}
