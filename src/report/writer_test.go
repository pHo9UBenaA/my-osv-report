package report_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/report"
)

func TestWriter_WriteMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")

	writer := report.NewWriter()
	ctx := context.Background()

	entries := []report.VulnerabilityEntry{
		{
			ID:          "GHSA-test-1234",
			Ecosystem:   "npm",
			Package:     "test-pkg",
			Downloads:   1000,
			GitHubStars: 100,
			Severity:    "HIGH",
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
			ID:          "GHSA-test-1234",
			Ecosystem:   "npm",
			Package:     "test-pkg",
			Downloads:   1000,
			GitHubStars: 100,
			Severity:    "HIGH",
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
			ID:          "GHSA-test-1234",
			Ecosystem:   "npm",
			Package:     "test-pkg",
			Downloads:   1000,
			GitHubStars: 100,
			Severity:    "HIGH",
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
