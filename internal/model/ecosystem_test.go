package model_test

import (
	"errors"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/model"
)

func TestModifiedCSVURL_EcosystemVariants(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "SimpleEcosystem_ReturnsDirectPath",
			eco:     model.NPM,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
		},
		{
			name:    "EcosystemWithSpace_PercentEncodesSpace",
			eco:     model.GitHubActions,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eco.ModifiedCSVURL()
			if got != tt.wantURL {
				t.Errorf("ModifiedCSVURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestSitemapURL_EcosystemVariants(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "SimpleEcosystem_ReturnsUnmodifiedName",
			eco:     model.NPM,
			wantURL: "https://osv.dev/sitemap_npm.xml",
		},
		{
			name:    "EcosystemWithSpace_ReplacesSpaceWithUnderscore",
			eco:     model.GitHubActions,
			wantURL: "https://osv.dev/sitemap_GitHub_Actions.xml",
		},
		{
			name:    "EcosystemWithHyphen_PreservesHyphen",
			eco:     model.OSSFuzz,
			wantURL: "https://osv.dev/sitemap_OSS-Fuzz.xml",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eco.SitemapURL()
			if got != tt.wantURL {
				t.Errorf("SitemapURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestValidate_EcosystemValidity(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantErr error
	}{
		{
			name:    "SupportedEcosystem_ReturnsNil",
			eco:     model.NPM,
			wantErr: nil,
		},
		{
			name:    "UnsupportedName_ReturnsErrInvalidEcosystem",
			eco:     model.Ecosystem("Unknown"),
			wantErr: model.ErrInvalidEcosystem,
		},
		{
			name:    "EcosystemWithSpace_ReturnsNil",
			eco:     model.GitHubActions,
			wantErr: nil,
		},
		{
			name:    "EmptyString_ReturnsErrInvalidEcosystem",
			eco:     model.Ecosystem(""),
			wantErr: model.ErrInvalidEcosystem,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.eco.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseEcosystems_InputVariants(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    []model.Ecosystem
		wantErr error
	}{
		{
			name:    "CommaSeparatedList_ReturnsParsedSlice",
			input:   "npm,PyPI,Go",
			want:    []model.Ecosystem{model.NPM, model.PyPI, model.Go},
			wantErr: nil,
		},
		{
			name:    "WhitespaceAroundEntries_TrimsAndParses",
			input:   " npm , PyPI , Go ",
			want:    []model.Ecosystem{model.NPM, model.PyPI, model.Go},
			wantErr: nil,
		},
		{
			name:    "EmptyString_ReturnsEmptySlice",
			input:   "",
			want:    []model.Ecosystem{},
			wantErr: nil,
		},
		{
			name:    "InvalidInMiddle_ReturnsErrInvalidEcosystem",
			input:   "npm,InvalidEco,PyPI",
			want:    nil,
			wantErr: model.ErrInvalidEcosystem,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := model.ParseEcosystems(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseEcosystems() error = %v, want %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseEcosystems() got %d ecosystems, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseEcosystems()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
