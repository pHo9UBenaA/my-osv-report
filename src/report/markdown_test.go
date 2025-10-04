package report_test

import (
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/report"
)

func TestMarkdownFormatter_Format(t *testing.T) {
	formatter := report.NewMarkdownFormatter()

	entries := []report.VulnerabilityEntry{
		{
			ID:          "GHSA-xxxx-yyyy-zzzz",
			Ecosystem:   "npm",
			Package:     "express",
			Downloads:   5678901,
			GitHubStars: 1234,
			Published:   "2025-10-01T00:00:00Z",
			Modified:    "2025-10-02T00:00:00Z",
			Severity:    "HIGH",
		},
		{
			ID:          "GHSA-aaaa-bbbb-cccc",
			Ecosystem:   "PyPI",
			Package:     "requests",
			Downloads:   0,
			GitHubStars: 0,
			Published:   "",
			Modified:    "",
			Severity:    "",
		},
	}

	result := formatter.Format(entries)

	// Check header
	if !strings.Contains(result, "| Ecosystem | Package | Source | Download | GitHub Star | Published | Modified | Severity |") {
		t.Errorf("missing header in result")
	}

	// Check separator
	if !strings.Contains(result, "| --- | --- | --- | --- | --- | --- | --- | --- |") {
		t.Errorf("missing separator in result")
	}

	// Check first entry
	if !strings.Contains(result, "| npm | express | GHSA-xxxx-yyyy-zzzz | 5678901 | 1234 | 2025-10-01T00:00:00Z | 2025-10-02T00:00:00Z | HIGH |") {
		t.Errorf("missing first entry in result")
	}

	// Check second entry with NA values
	if !strings.Contains(result, "| PyPI | requests | GHSA-aaaa-bbbb-cccc | NA | NA | NA | NA | NA |") {
		t.Errorf("missing second entry with NA values in result")
	}
}
