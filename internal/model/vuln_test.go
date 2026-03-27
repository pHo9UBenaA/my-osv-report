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

func TestFilterByCursor_InputVariants(t *testing.T) {
	cases := []struct {
		name    string
		entries []model.Entry
		cursor  time.Time
		wantLen int
	}{
		{
			name: "MixedTimestamps_ReturnsOnlyNewer",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T11:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T13:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 2,
		},
		{
			name: "AllBeforeCursor_ReturnsEmpty",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
			},
			cursor:  mustParseTime("2025-10-04T10:00:00Z"),
			wantLen: 0,
		},
		{
			name:    "NilSlice_ReturnsEmpty",
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

func TestMaxModified_InputVariants(t *testing.T) {
	cases := []struct {
		name    string
		entries []model.Entry
		want    time.Time
	}{
		{
			name: "MultipleEntries_ReturnsLatest",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T13:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T11:00:00Z")},
			},
			want: mustParseTime("2025-10-04T13:00:00Z"),
		},
		{
			name:    "EmptySlice_ReturnsZeroTime",
			entries: nil,
			want:    time.Time{},
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
