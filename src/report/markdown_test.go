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

func TestMarkdownFormatter_Format_EscapesSpecialCharacters(t *testing.T) {
	formatter := report.NewMarkdownFormatter()

	entries := []report.VulnerabilityEntry{
		{
			ID:          "GHSA-test-0001",
			Ecosystem:   "npm",
			Package:     "pkg-with-|pipe|chars",
			Downloads:   100,
			GitHubStars: 50,
			Published:   "2025-10-01",
			Modified:    "2025-10-02",
			Severity:    "HIGH|CRITICAL",
		},
		{
			ID:          "<script>alert('xss')</script>",
			Ecosystem:   "PyPI",
			Package:     "[dangerous](http://evil.com)",
			Downloads:   200,
			GitHubStars: 10,
			Published:   "2025-10-03",
			Modified:    "2025-10-04",
			Severity:    "*emphasis*",
		},
	}

	result := formatter.Format(entries)

	// Pipe characters should be escaped to prevent breaking table structure
	if strings.Contains(result, "pkg-with-|pipe|chars") {
		t.Errorf("pipe characters in package name should be escaped, got: %s", result)
	}
	if !strings.Contains(result, "pkg-with-\\|pipe\\|chars") {
		t.Errorf("expected escaped pipe characters in package name")
	}

	// HTML tags should be escaped
	if strings.Contains(result, "<script>") {
		t.Errorf("HTML tags should be escaped, got: %s", result)
	}

	// Markdown links should be escaped
	if strings.Contains(result, "[dangerous](http://evil.com)") {
		t.Errorf("markdown links should be escaped, got: %s", result)
	}

	// Markdown emphasis should be escaped
	if strings.Contains(result, "*emphasis*") && !strings.Contains(result, "\\*emphasis\\*") {
		t.Errorf("markdown emphasis characters should be escaped, got: %s", result)
	}
}
