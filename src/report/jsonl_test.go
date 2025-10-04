package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/report"
)

func TestJSONLFormatter_Format(t *testing.T) {
	formatter := report.NewJSONLFormatter()

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
	if first["downloads"] != float64(5678901) {
		t.Errorf("first.downloads = %v, want 5678901", first["downloads"])
	}
	if first["published"] != "2025-10-01T00:00:00Z" {
		t.Errorf("first.published = %v, want 2025-10-01T00:00:00Z", first["published"])
	}

	// Check second line with NA values
	var second map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["downloads"] != "NA" {
		t.Errorf("second.downloads = %v, want NA", second["downloads"])
	}
	if second["github_stars"] != "NA" {
		t.Errorf("second.github_stars = %v, want NA", second["github_stars"])
	}
	if second["published"] != "NA" {
		t.Errorf("second.published = %v, want NA", second["published"])
	}
	if second["modified"] != "NA" {
		t.Errorf("second.modified = %v, want NA", second["modified"])
	}
	if second["severity"] != "NA" {
		t.Errorf("second.severity = %v, want NA", second["severity"])
	}
}
