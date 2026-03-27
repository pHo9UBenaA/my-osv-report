package model_test

import (
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/model"
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFilterByCursor(t *testing.T) {
	cases := []struct {
		name    string
		entries []model.Entry
		cursor  time.Time
		wantLen int
	}{
		{
			name: "filter entries after cursor",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T11:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T13:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 2,
		},
		{
			name: "all entries before cursor",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 0,
		},
		{
			name:    "empty entries",
			entries: nil,
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 0,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result := model.FilterByCursor(tt.entries, tt.cursor)
			if len(result) != tt.wantLen {
				t.Errorf("len(result) = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestMaxModified(t *testing.T) {
	cases := []struct {
		name    string
		entries []model.Entry
		want    time.Time
	}{
		{
			name: "returns latest modified time",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T13:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T11:00:00Z")},
			},
			want: mustParseTime("2025-10-04T13:00:00Z"),
		},
		{
			name: "single entry",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
			},
			want: mustParseTime("2025-10-04T09:00:00Z"),
		},
		{
			name:    "empty entries returns zero time",
			entries: nil,
			want:    time.Time{},
		},
		{
			name: "entries not sorted returns max anyway",
			entries: []model.Entry{
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T13:00:00Z")},
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T11:00:00Z")},
			},
			want: mustParseTime("2025-10-04T13:00:00Z"),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := model.MaxModified(tt.entries)
			if !got.Equal(tt.want) {
				t.Errorf("MaxModified() = %v, want %v", got, tt.want)
			}
		})
	}
}
