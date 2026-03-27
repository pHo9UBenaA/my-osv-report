package report_test

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestFormatCSV_MixedEntries_ProducesHeaderAndDataRows(t *testing.T) {
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

	result, err := report.FormatCSV(entries)
	if err != nil {
		t.Fatalf("FormatCSV() error = %v", err)
	}

	if !strings.Contains(result, "ecosystem,package,id,published,modified,severity_base_score,severity_vector") {
		t.Errorf("missing header in result")
	}

	if !strings.Contains(result, "npm,express,GHSA-xxxx-yyyy-zzzz,2025-10-01T00:00:00Z,2025-10-02T00:00:00Z,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
		t.Errorf("missing first entry in result")
	}

	if !strings.Contains(result, "PyPI,requests,GHSA-aaaa-bbbb-cccc,NA,NA,NA,NA") {
		t.Errorf("missing second entry with NA values in result")
	}
}

func TestFormatCSV_FormulaInjectionPrefixes_EscapedWithQuote(t *testing.T) {
	tests := []struct {
		name        string
		entry       report.VulnerabilityEntry
		wantPackage string
	}{
		{
			name: "EqualsPrefix_InPackageName",
			entry: report.VulnerabilityEntry{
				ID: "GHSA-test-1234", Ecosystem: "npm",
				Package: "=malicious-package", SeverityVector: "HIGH",
			},
			wantPackage: "'=malicious-package",
		},
		{
			name: "PlusPrefix_InPackageName",
			entry: report.VulnerabilityEntry{
				ID: "GHSA-test-1234", Ecosystem: "npm",
				Package: "+malicious-package", SeverityVector: "HIGH",
			},
			wantPackage: "'+malicious-package",
		},
		{
			name: "MinusPrefix_InPackageName",
			entry: report.VulnerabilityEntry{
				ID: "GHSA-test-1234", Ecosystem: "npm",
				Package: "-malicious-package", SeverityVector: "HIGH",
			},
			wantPackage: "'-malicious-package",
		},
		{
			name: "AtSignPrefix_InPackageName",
			entry: report.VulnerabilityEntry{
				ID: "GHSA-test-1234", Ecosystem: "npm",
				Package: "@scoped/package", SeverityVector: "HIGH",
			},
			wantPackage: "'@scoped/package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := report.FormatCSV([]report.VulnerabilityEntry{tt.entry})
			if err != nil {
				t.Fatalf("FormatCSV() error = %v", err)
			}

			r := csv.NewReader(strings.NewReader(result))
			records, err := r.ReadAll()
			if err != nil {
				t.Fatalf("csv.ReadAll() error = %v", err)
			}
			if len(records) < 2 {
				t.Fatalf("expected at least 2 records, got %d", len(records))
			}

			gotPackage := records[1][1]
			if gotPackage != tt.wantPackage {
				t.Errorf("package field = %q, want %q", gotPackage, tt.wantPackage)
			}
		})
	}
}

func TestFormatCSV_LeadingWhitespaceThenDangerousChar_StillEscaped(t *testing.T) {
	entry := report.VulnerabilityEntry{
		ID:             "\n=INJECT",
		Ecosystem:      " npm",
		Package:        "\t=cmd|'/c calc'!A1",
		SeverityVector: "\r@ALERT",
	}

	result, err := report.FormatCSV([]report.VulnerabilityEntry{entry})
	if err != nil {
		t.Fatalf("FormatCSV() error = %v", err)
	}

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
