package osv_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		name         string
		line         string
		wantID       string
		wantModified time.Time
		wantErr      bool
	}{
		{
			name:         "valid line",
			line:         "GHSA-xxxx-yyyy-zzzz,2025-10-04T12:34:56Z",
			wantID:       "GHSA-xxxx-yyyy-zzzz",
			wantModified: mustParseTime("2025-10-04T12:34:56Z"),
			wantErr:      false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			id, modified, err := osv.ParseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
			if !modified.Equal(tt.wantModified) {
				t.Errorf("modified = %v, want %v", modified, tt.wantModified)
			}
		})
	}
}

func TestParseCSV(t *testing.T) {
	cases := []struct {
		name    string
		csv     string
		wantLen int
		wantErr bool
	}{
		{
			name: "multiple lines",
			csv: `GHSA-aaaa-bbbb-cccc,2025-10-04T10:00:00Z
GHSA-dddd-eeee-ffff,2025-10-04T11:00:00Z
GHSA-gggg-hhhh-iiii,2025-10-04T12:00:00Z`,
			wantLen: 3,
			wantErr: false,
		},
		{
			name:    "empty input",
			csv:     "",
			wantLen: 0,
			wantErr: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.csv)
			entries, err := osv.ParseCSV(r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCSV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(entries) != tt.wantLen {
				t.Errorf("len(entries) = %d, want %d", len(entries), tt.wantLen)
			}
		})
	}
}

func TestFilterByCursor(t *testing.T) {
	cases := []struct {
		name    string
		entries []osv.Entry
		cursor  time.Time
		wantLen int
	}{
		{
			name: "filter entries after cursor",
			entries: []osv.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T11:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T13:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 2,
		},
		{
			name: "all entries before cursor",
			entries: []osv.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 0,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result := osv.FilterByCursor(tt.entries, tt.cursor)
			if len(result) != tt.wantLen {
				t.Errorf("len(result) = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
