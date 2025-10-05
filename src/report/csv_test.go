package report_test

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/report"
)

func TestCSVFormatter_Format(t *testing.T) {
	formatter := report.NewCSVFormatter()

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
	if !strings.Contains(result, "ecosystem,package,source,downloads,github_stars,published,modified,severity") {
		t.Errorf("missing header in result")
	}

	// Check first entry
	if !strings.Contains(result, "npm,express,GHSA-xxxx-yyyy-zzzz,5678901,1234,2025-10-01T00:00:00Z,2025-10-02T00:00:00Z,HIGH") {
		t.Errorf("missing first entry in result")
	}

	// Check second entry with NA values
	if !strings.Contains(result, "PyPI,requests,GHSA-aaaa-bbbb-cccc,NA,NA,NA,NA,NA") {
		t.Errorf("missing second entry with NA values in result")
	}
}

func TestCSVFormatter_FormulaInjectionPrevention(t *testing.T) {
	formatter := report.NewCSVFormatter()

	tests := []struct {
		name     string
		entry    report.VulnerabilityEntry
		wantSafe bool // true if dangerous prefixes should be escaped
	}{
		{
			name: "package name starting with =",
			entry: report.VulnerabilityEntry{
				ID:        "GHSA-test-1234",
				Ecosystem: "npm",
				Package:   "=malicious-package",
				Severity:  "HIGH",
			},
			wantSafe: true,
		},
		{
			name: "package name starting with +",
			entry: report.VulnerabilityEntry{
				ID:        "GHSA-test-1234",
				Ecosystem: "npm",
				Package:   "+malicious-package",
				Severity:  "HIGH",
			},
			wantSafe: true,
		},
		{
			name: "package name starting with -",
			entry: report.VulnerabilityEntry{
				ID:        "GHSA-test-1234",
				Ecosystem: "npm",
				Package:   "-malicious-package",
				Severity:  "HIGH",
			},
			wantSafe: true,
		},
		{
			name: "package name starting with @",
			entry: report.VulnerabilityEntry{
				ID:        "GHSA-test-1234",
				Ecosystem: "npm",
				Package:   "@scoped/package",
				Severity:  "HIGH",
			},
			wantSafe: true,
		},
		{
			name: "ID starting with =",
			entry: report.VulnerabilityEntry{
				ID:        "=SUM(A1:A10)",
				Ecosystem: "npm",
				Package:   "safe-package",
				Severity:  "HIGH",
			},
			wantSafe: true,
		},
		{
			name: "severity starting with +",
			entry: report.VulnerabilityEntry{
				ID:        "GHSA-test-1234",
				Ecosystem: "npm",
				Package:   "safe-package",
				Severity:  "+cmd|'/c calc'!A1",
			},
			wantSafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.Format([]report.VulnerabilityEntry{tt.entry})

			// Check that dangerous characters are not at the start of fields
			// when interpreted as CSV (after header line)
			lines := strings.Split(result, "\n")
			if len(lines) < 2 {
				t.Fatalf("expected at least 2 lines, got %d", len(lines))
			}

			dataLine := lines[1]
			if tt.wantSafe {
				// Should not start with dangerous characters
				dangerousPrefixes := []string{"=", "+", "-", "@"}
				for _, prefix := range dangerousPrefixes {
					// Check if any field in the data line starts with a dangerous prefix
					// We need to properly parse CSV to check each field
					fields := strings.Split(dataLine, ",")
					for i, field := range fields {
						// Trim quotes if present (proper CSV escaping)
						trimmed := strings.Trim(field, "\"")
						if strings.HasPrefix(trimmed, prefix) {
							// If the original value started with this prefix, it should be escaped
							if (i == 1 && strings.HasPrefix(tt.entry.Package, prefix)) ||
								(i == 2 && strings.HasPrefix(tt.entry.ID, prefix)) ||
								(i == 7 && strings.HasPrefix(tt.entry.Severity, prefix)) {
								t.Errorf("field %d should escape dangerous prefix %q but got: %q", i, prefix, field)
							}
						}
					}
				}
			}
		})
	}
}

func TestCSVFormatter_FormulaInjectionPrevention_WithLeadingWhitespace(t *testing.T) {
	formatter := report.NewCSVFormatter()

	entry := report.VulnerabilityEntry{
		ID:        "\n=INJECT",
		Ecosystem: " npm",
		Package:   "\t=cmd|'/c calc'!A1",
		Severity:  "\r@ALERT",
	}

	result := formatter.Format([]report.VulnerabilityEntry{entry})

	r := csv.NewReader(strings.NewReader(result))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV output: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records (header + entry), got %d", len(records))
	}

	data := records[1]
	unsafePrefixes := []string{"=", "+", "-", "@"}

	for idx, field := range data {
		trimmed := strings.TrimLeft(field, " \t\r\n")
		for _, prefix := range unsafePrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				t.Fatalf("field %d should escape prefix %q but got %q", idx, prefix, field)
			}
		}
	}
}
