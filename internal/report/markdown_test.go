package report_test

import (
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestMarkdownFormatter_Format(t *testing.T) {
	entries := []report.VulnerabilityEntry{
		{
			ID:        "GHSA-xxxx-yyyy-zzzz",
			Ecosystem: "npm",
			Package:   "express",
			Published: "2025-10-01T00:00:00Z",
			Modified:  "2025-10-02T00:00:00Z",
			SeverityBaseScore: func() *float64 {
				val := 9.8
				return &val
			}(),
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:        "GHSA-aaaa-bbbb-cccc",
			Ecosystem: "PyPI",
			Package:   "requests",
			Published: "",
			Modified:  "",
		},
	}

	result := report.FormatMarkdown(entries)

	// Check header
	if !strings.Contains(result, "| Ecosystem | Package | Source | Published | Modified | Severity: Base Score | Severity: Vector String |") {
		t.Errorf("missing header in result")
	}

	// Check separator
	if !strings.Contains(result, "| --- | --- | --- | --- | --- | --- | --- |") {
		t.Errorf("missing separator in result")
	}

	// Check first entry
	if !strings.Contains(result, "| npm | express | GHSA-xxxx-yyyy-zzzz | 2025-10-01T00:00:00Z | 2025-10-02T00:00:00Z | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |") {
		t.Errorf("missing first entry in result")
	}

	// Check second entry with NA values
	if !strings.Contains(result, "| PyPI | requests | GHSA-aaaa-bbbb-cccc | NA | NA | NA | NA |") {
		t.Errorf("missing second entry with NA values in result")
	}
}

func TestMarkdownFormatter_Format_EscapesSpecialCharacters(t *testing.T) {
	entries := []report.VulnerabilityEntry{
		{
			ID:             "GHSA-test-0001",
			Ecosystem:      "npm",
			Package:        "pkg-with-|pipe|chars",
			Published:      "2025-10-01",
			Modified:       "2025-10-02",
			SeverityVector: "HIGH|CRITICAL",
			SeverityBaseScore: func() *float64 {
				val := 7.2
				return &val
			}(),
		},
		{
			ID:             "<script>alert('xss')</script>",
			Ecosystem:      "PyPI",
			Package:        "[dangerous](http://evil.com)",
			Published:      "2025-10-03",
			Modified:       "2025-10-04",
			SeverityVector: "*emphasis*",
		},
	}

	result := report.FormatMarkdown(entries)

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
