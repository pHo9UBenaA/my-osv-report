package model_test

import (
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/model"
)

func TestParseVector_ValidCVSS31Vector_ReturnsBaseScore(t *testing.T) {
	score, err := model.ParseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 9.8 {
		t.Fatalf("ParseVector() score = %v, want 9.8", score)
	}
}

func TestParseVector_PlainFloatString_ReturnsParsedValue(t *testing.T) {
	score, err := model.ParseVector("7.5")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 7.5 {
		t.Fatalf("ParseVector() score = %v, want 7.5", score)
	}
}

func TestParseVector_UnsupportedCVSS4_ReturnsError(t *testing.T) {
	if _, err := model.ParseVector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); err == nil {
		t.Fatalf("ParseVector() expected error for unsupported version")
	}
}

func TestExtractFromOSV_ValidCVSS3Entry_ReturnsScoreAndVector(t *testing.T) {
	base, vector, err := model.ExtractFromOSV([]model.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
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

func TestExtractFromOSV_UnparseableVector_ReturnsErrorWithVector(t *testing.T) {
	base, vector, err := model.ExtractFromOSV([]model.SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N"}})
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
