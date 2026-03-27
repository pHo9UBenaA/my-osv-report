package model_test

import (
	"errors"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/internal/model"
)

func TestEcosystem_ModifiedCSVURL(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "npm",
			eco:     model.NPM,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
		},
		{
			name:    "PyPI",
			eco:     model.PyPI,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
		},
		{
			name:    "Go",
			eco:     model.Go,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
		},
		{
			name:    "GitHub Actions with space",
			eco:     model.GitHubActions,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
		},
		{
			name:    "RubyGems",
			eco:     model.RubyGems,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip",
		},
		{
			name:    "Red Hat with space",
			eco:     model.RedHat,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip",
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

func TestEcosystem_SitemapURL(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "npm",
			eco:     model.NPM,
			wantURL: "https://osv.dev/sitemap_npm.xml",
		},
		{
			name:    "PyPI",
			eco:     model.PyPI,
			wantURL: "https://osv.dev/sitemap_PyPI.xml",
		},
		{
			name:    "Go",
			eco:     model.Go,
			wantURL: "https://osv.dev/sitemap_Go.xml",
		},
		{
			name:    "GitHub Actions with space",
			eco:     model.GitHubActions,
			wantURL: "https://osv.dev/sitemap_GitHub_Actions.xml",
		},
		{
			name:    "Red Hat with space",
			eco:     model.RedHat,
			wantURL: "https://osv.dev/sitemap_Red_Hat.xml",
		},
		{
			name:    "OSS-Fuzz with hyphen",
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

func TestEcosystem_Validate(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantErr error
	}{
		{
			name:    "valid: npm",
			eco:     model.NPM,
			wantErr: nil,
		},
		{
			name:    "valid: PyPI",
			eco:     model.PyPI,
			wantErr: nil,
		},
		{
			name:    "valid: Go",
			eco:     model.Go,
			wantErr: nil,
		},
		{
			name:    "valid: GitHub Actions",
			eco:     model.GitHubActions,
			wantErr: nil,
		},
		{
			name:    "invalid: unknown",
			eco:     model.Ecosystem("Unknown"),
			wantErr: model.ErrInvalidEcosystem,
		},
		{
			name:    "invalid: empty",
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

func TestParseEcosystems(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    []model.Ecosystem
		wantErr error
	}{
		{
			name:    "single ecosystem",
			input:   "npm",
			want:    []model.Ecosystem{model.NPM},
			wantErr: nil,
		},
		{
			name:    "multiple ecosystems",
			input:   "npm,PyPI,Go",
			want:    []model.Ecosystem{model.NPM, model.PyPI, model.Go},
			wantErr: nil,
		},
		{
			name:    "ecosystems with spaces",
			input:   "GitHub Actions,Red Hat",
			want:    []model.Ecosystem{model.GitHubActions, model.RedHat},
			wantErr: nil,
		},
		{
			name:    "ecosystems with trimming",
			input:   " npm , PyPI , Go ",
			want:    []model.Ecosystem{model.NPM, model.PyPI, model.Go},
			wantErr: nil,
		},
		{
			name:    "empty string",
			input:   "",
			want:    []model.Ecosystem{},
			wantErr: nil,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			want:    []model.Ecosystem{},
			wantErr: nil,
		},
		{
			name:    "invalid ecosystem",
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
