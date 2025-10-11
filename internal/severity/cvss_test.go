package severity_test

import (
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
	"github.com/pHo9UBenaA/osv-scraper/internal/severity"
)

func TestParseVector_CVSS3(t *testing.T) {
	score, err := severity.ParseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 9.8 {
		t.Fatalf("ParseVector() score = %v, want 9.8", score)
	}
}

func TestParseVector_InvalidVersion(t *testing.T) {
	if _, err := severity.ParseVector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); err == nil {
		t.Fatalf("ParseVector() expected error for unsupported version")
	}
}

func TestParseVector_Numeric(t *testing.T) {
	score, err := severity.ParseVector("7.5")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 7.5 {
		t.Fatalf("ParseVector() score = %v, want 7.5", score)
	}
}

func TestExtractFromOSV(t *testing.T) {
	base, vector, err := severity.ExtractFromOSV([]osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
	if err != nil {
		t.Fatalf("ExtractFromOSV() error = %v", err)
	}
	if vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("ExtractFromOSV() vector = %q", vector)
	}
	if base == nil || *base != 9.8 {
		t.Fatalf("ExtractFromOSV() base = %v, want 9.8", base)
	}
}

func TestExtractFromOSV_ParseError(t *testing.T) {
	base, vector, err := severity.ExtractFromOSV([]osv.Severity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N"}})
	if err == nil {
		t.Fatalf("ExtractFromOSV() expected error")
	}
	if vector != "CVSS:4.0/AV:N" {
		t.Fatalf("ExtractFromOSV() vector = %q", vector)
	}
	if base != nil {
		t.Fatalf("ExtractFromOSV() base = %v, want nil", base)
	}
}
