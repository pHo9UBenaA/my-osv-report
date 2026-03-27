package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestWriteCSV_ValidEntries_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.csv")

	entries := []report.VulnerabilityEntry{
		{
			ID:        "GHSA-test-1234",
			Ecosystem: "npm",
			Package:   "test-pkg",
			SeverityBaseScore: func() *float64 {
				val := 7.5
				return &val
			}(),
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		},
	}

	if err := report.WriteCSV(outputPath, entries); err != nil {
		t.Fatalf("WriteCSV() error = %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("output file was not created at %s", outputPath)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("output file is empty")
	}
}

func TestWriteCSV_CreatedFile_Has0600Permissions(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report-perm.csv")

	entries := []report.VulnerabilityEntry{
		{
			ID:        "GHSA-test-1234",
			Ecosystem: "npm",
			Package:   "test-pkg",
			SeverityBaseScore: func() *float64 {
				val := 7.5
				return &val
			}(),
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		},
	}

	if err := report.WriteCSV(outputPath, entries); err != nil {
		t.Fatalf("WriteCSV() error = %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("file permissions = %04o, want 0600", mode)
	}
}
