package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/report"
)

func TestFormatJSONL_MixedEntries_ProducesOneLinePerEntry(t *testing.T) {
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

	result, err := report.FormatJSONL(entries)
	if err != nil {
		t.Fatalf("FormatJSONL() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	if first["id"] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("first.id = %v, want GHSA-xxxx-yyyy-zzzz", first["id"])
	}
	if first["severity_base_score"] != "9.8" {
		t.Errorf("first.severity_base_score = %v, want 9.8", first["severity_base_score"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["published"] != "NA" {
		t.Errorf("second.published = %v, want NA", second["published"])
	}
	if second["severity_base_score"] != "NA" {
		t.Errorf("second.severity_base_score = %v, want NA", second["severity_base_score"])
	}
}

func TestFormatJSONL_DangerousCharsAndControlCodes_SafelyJSONEncoded(t *testing.T) {
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
			Package:        "test\npkg",
			Published:      "value\twith\ttabs",
			Modified:       "",
			SeverityVector: "value\rwith\rcarriage",
		},
	}

	result, err := report.FormatJSONL(entries)
	if err != nil {
		t.Fatalf("FormatJSONL() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	if first["id"] != "=cmd|'/c calc'!A1" {
		t.Errorf("first.id = %v, want =cmd|'/c calc'!A1", first["id"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["package"] != "test\npkg" {
		t.Errorf("second.package = %v, want test\\npkg", second["package"])
	}

	if !strings.Contains(result, `"package":"test\npkg"`) {
		t.Error("expected newline to be escaped as \\n in JSON output")
	}
}
