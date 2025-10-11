package report_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestWriter_WriteMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")

	writer := report.NewWriter()
	ctx := context.Background()

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

	if err := writer.WriteMarkdown(ctx, outputPath, entries); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("output file was not created at %s", outputPath)
	}

	// Verify content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Errorf("output file is empty")
	}
}

func TestWriter_WriteCSV(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.csv")

	writer := report.NewWriter()
	ctx := context.Background()

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

	if err := writer.WriteCSV(ctx, outputPath, entries); err != nil {
		t.Fatalf("WriteCSV() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("output file was not created at %s", outputPath)
	}
}

func TestWriter_WriteJSONL(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.jsonl")

	writer := report.NewWriter()
	ctx := context.Background()

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

	if err := writer.WriteJSONL(ctx, outputPath, entries); err != nil {
		t.Fatalf("WriteJSONL() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("output file was not created at %s", outputPath)
	}
}

func TestWriter_FilePermissions0600(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report-perm.csv")

	writer := report.NewWriter()
	ctx := context.Background()

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

	if err := writer.WriteCSV(ctx, outputPath, entries); err != nil {
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
