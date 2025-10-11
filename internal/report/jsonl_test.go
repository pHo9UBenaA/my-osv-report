package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestJSONLFormatter_Format(t *testing.T) {
	formatter := report.NewJSONLFormatter()

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

	result := formatter.Format(entries)

	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Check first line
	var first map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	if first["source"] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("first.source = %v, want GHSA-xxxx-yyyy-zzzz", first["source"])
	}
	if first["published"] != "2025-10-01T00:00:00Z" {
		t.Errorf("first.published = %v, want 2025-10-01T00:00:00Z", first["published"])
	}
	if first["severity_base_score"] != "9.8" {
		t.Errorf("first.severity_base_score = %v, want 9.8", first["severity_base_score"])
	}
	if first["severity_vector"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("first.severity_vector = %v, want CVSS vector", first["severity_vector"])
	}

	// Check second line with NA values
	var second map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["published"] != "NA" {
		t.Errorf("second.published = %v, want NA", second["published"])
	}
	if second["modified"] != "NA" {
		t.Errorf("second.modified = %v, want NA", second["modified"])
	}
	if second["severity_base_score"] != "NA" {
		t.Errorf("second.severity_base_score = %v, want NA", second["severity_base_score"])
	}
	if second["severity_vector"] != "NA" {
		t.Errorf("second.severity_vector = %v, want NA", second["severity_vector"])
	}
}

func TestJSONLFormatter_SafetyForExcelPrefixesAndControlCharacters(t *testing.T) {
	formatter := report.NewJSONLFormatter()

	entries := []report.VulnerabilityEntry{
		{
			ID:             "=cmd|'/c calc'!A1",
			Ecosystem:      "+EXEC",
			Package:        "-dangerous",
			Published:      "@FORMULA",
			Modified:       "2025-10-02T00:00:00Z",
			SeverityVector: "=1+1",
		},
		{
			ID:             "GHSA-ctrl-char",
			Ecosystem:      "npm",
			Package:        "test\npkg", // newline
			Published:      "value\twith\ttabs",
			Modified:       "",
			SeverityVector: "value\rwith\rcarriage",
		},
	}

	result := formatter.Format(entries)
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Verify first line with Excel-like prefixes
	var first map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	// JSON should safely encode these as strings
	if first["source"] != "=cmd|'/c calc'!A1" {
		t.Errorf("first.source = %v, want =cmd|'/c calc'!A1", first["source"])
	}
	if first["ecosystem"] != "+EXEC" {
		t.Errorf("first.ecosystem = %v, want +EXEC", first["ecosystem"])
	}
	if first["package"] != "-dangerous" {
		t.Errorf("first.package = %v, want -dangerous", first["package"])
	}
	if first["published"] != "@FORMULA" {
		t.Errorf("first.published = %v, want @FORMULA", first["published"])
	}
	if first["severity_vector"] != "=1+1" {
		t.Errorf("first.severity_vector = %v, want =1+1", first["severity_vector"])
	}

	// Verify second line with control characters
	var second map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["package"] != "test\npkg" {
		t.Errorf("second.package = %v, want test\\npkg", second["package"])
	}
	if second["published"] != "value\twith\ttabs" {
		t.Errorf("second.published = %v, want value\\twith\\ttabs", second["published"])
	}
	if second["severity_vector"] != "value\rwith\rcarriage" {
		t.Errorf("second.severity_vector = %v, want value\\rwith\\rcarriage", second["severity_vector"])
	}

	// Verify that raw output has properly escaped JSON
	if !strings.Contains(result, `"source":"=cmd|'/c calc'!A1"`) {
		t.Error("expected source to be properly JSON-escaped in output")
	}
	if !strings.Contains(result, `"package":"test\npkg"`) {
		t.Error("expected newline to be escaped as \\n in JSON output")
	}
}
