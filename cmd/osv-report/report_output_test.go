package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/app"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

func TestGenerateReport_Integration_OutputFileHasTimestamp(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	fixedTime := time.Date(2025, 1, 1, 9, 0, 0, 0, time.UTC)

	dbPath := filepath.Join(tmpDir, "test.db")
	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = st.Close() }()

	vuln := store.Vulnerability{
		ID:                "GHSA-test-1234",
		Modified:          fixedTime,
		Published:         fixedTime,
		Summary:           "test summary",
		Details:           "test details",
		SeverityBaseScore: sql.NullFloat64{Float64: 9.8, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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

	opts := app.ReportOptions{
		Format:     "markdown",
		OutputDir:  tmpDir,
		FilePrefix: "report",
		Ecosystem:  "",
		Diff:       false,
	}

	if err := app.GenerateReport(ctx, st, opts); err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	var foundReport string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".md" && !entry.IsDir() {
			foundReport = entry.Name()
			break
		}
	}
	if foundReport == "" {
		t.Fatalf("timestamped report not found in %s", tmpDir)
	}

	if foundReport == "report.md" {
		t.Fatalf("expected timestamped filename, got %s", foundReport)
	}
}

func TestGenerateReport_Integration_DiffModeUpdatesSnapshot(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = st.Close() }()

	vuln1 := store.Vulnerability{
		ID:                "GHSA-initial-1",
		Modified:          time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 9.8, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := st.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(vuln1) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-initial-1", Ecosystem: "npm", Package: "pkg1"}); err != nil {
		t.Fatalf("SaveAffected(vuln1) error = %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:                "GHSA-initial-2",
		Modified:          time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 6.4, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := st.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(vuln2) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-initial-2", Ecosystem: "npm", Package: "pkg2"}); err != nil {
		t.Fatalf("SaveAffected(vuln2) error = %v", err)
	}

	opts := app.ReportOptions{
		Format:     "jsonl",
		OutputDir:  tmpDir,
		FilePrefix: "report",
		Ecosystem:  "",
		Diff:       true,
	}

	if err := app.GenerateReport(ctx, st, opts); err != nil {
		t.Fatalf("GenerateReport() first run error = %v", err)
	}

	unreportedAfterFirst, err := st.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() after first run error = %v", err)
	}
	if len(unreportedAfterFirst) != 0 {
		t.Errorf("After first run, expected 0 unreported vulnerabilities, got %d", len(unreportedAfterFirst))
	}

	vuln3 := store.Vulnerability{
		ID:                "GHSA-new-3",
		Modified:          time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 5.7, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
	}
	if err := st.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(vuln3) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-new-3", Ecosystem: "npm", Package: "pkg3"}); err != nil {
		t.Fatalf("SaveAffected(vuln3) error = %v", err)
	}

	opts.FilePrefix = "report2"
	if err := app.GenerateReport(ctx, st, opts); err != nil {
		t.Fatalf("GenerateReport() second run error = %v", err)
	}

	finalUnreported, err := st.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() after second run error = %v", err)
	}
	if len(finalUnreported) != 0 {
		t.Errorf("After second run, expected 0 unreported vulnerabilities, got %d", len(finalUnreported))
	}

	allEntriesAfter, err := st.GetVulnerabilitiesForReport(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport() after second run error = %v", err)
	}
	if len(allEntriesAfter) != 3 {
		t.Fatalf("Expected 3 vulnerabilities in DB after second run, got %d", len(allEntriesAfter))
	}
}

func TestGenerateReport_Integration_DiffModeRespectsEcosystemFilter(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = st.Close() }()

	npmVuln := store.Vulnerability{
		ID:                "GHSA-npm-1",
		Modified:          time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 9.0, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := st.SaveVulnerability(ctx, npmVuln); err != nil {
		t.Fatalf("SaveVulnerability(npmVuln) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-npm-1", Ecosystem: "npm", Package: "npm-pkg"}); err != nil {
		t.Fatalf("SaveAffected(npmVuln) error = %v", err)
	}

	pypiVuln := store.Vulnerability{
		ID:                "GHSA-pypi-1",
		Modified:          time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 5.5, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
	}
	if err := st.SaveVulnerability(ctx, pypiVuln); err != nil {
		t.Fatalf("SaveVulnerability(pypiVuln) error = %v", err)
	}
	if err := st.SaveAffected(ctx, store.Affected{VulnID: "GHSA-pypi-1", Ecosystem: "PyPI", Package: "pypi-pkg"}); err != nil {
		t.Fatalf("SaveAffected(pypiVuln) error = %v", err)
	}

	opts := app.ReportOptions{
		Format:     "jsonl",
		OutputDir:  tmpDir,
		FilePrefix: "npm-report",
		Ecosystem:  "npm",
		Diff:       true,
	}

	if err := app.GenerateReport(ctx, st, opts); err != nil {
		t.Fatalf("GenerateReport() npm-only error = %v", err)
	}

	npmUnreported, err := st.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm) error = %v", err)
	}
	if len(npmUnreported) != 0 {
		t.Errorf("After npm report, expected 0 unreported npm vulnerabilities, got %d", len(npmUnreported))
	}

	pypiUnreported, err := st.GetUnreportedVulnerabilities(ctx, "PyPI")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(PyPI) error = %v", err)
	}
	if len(pypiUnreported) != 1 {
		t.Errorf("PyPI vulnerabilities should remain unreported after npm-only report, got %d unreported", len(pypiUnreported))
	}
}
