package ecosystem_test

import (
	"errors"
	"testing"

	"github.com/pHo9UBenaA/osv-scraper/src/ecosystem"
)

func TestEcosystem_ModifiedCSVURL(t *testing.T) {
	cases := []struct {
		name    string
		eco     ecosystem.Ecosystem
		wantURL string
	}{
		{
			name:    "npm",
			eco:     ecosystem.NPM,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
		},
		{
			name:    "PyPI",
			eco:     ecosystem.PyPI,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
		},
		{
			name:    "Go",
			eco:     ecosystem.Go,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
		},
		{
			name:    "GitHub Actions with space",
			eco:     ecosystem.GitHubActions,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
		},
		{
			name:    "RubyGems",
			eco:     ecosystem.RubyGems,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip",
		},
		{
			name:    "Red Hat with space",
			eco:     ecosystem.RedHat,
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
		eco     ecosystem.Ecosystem
		wantURL string
	}{
		{
			name:    "npm",
			eco:     ecosystem.NPM,
			wantURL: "https://osv.dev/sitemap_npm.xml",
		},
		{
			name:    "PyPI",
			eco:     ecosystem.PyPI,
			wantURL: "https://osv.dev/sitemap_PyPI.xml",
		},
		{
			name:    "Go",
			eco:     ecosystem.Go,
			wantURL: "https://osv.dev/sitemap_Go.xml",
		},
		{
			name:    "GitHub Actions with space",
			eco:     ecosystem.GitHubActions,
			wantURL: "https://osv.dev/sitemap_GitHub_Actions.xml",
		},
		{
			name:    "Red Hat with space",
			eco:     ecosystem.RedHat,
			wantURL: "https://osv.dev/sitemap_Red_Hat.xml",
		},
		{
			name:    "OSS-Fuzz with hyphen",
			eco:     ecosystem.OSSFuzz,
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
		eco     ecosystem.Ecosystem
		wantErr error
	}{
		{
			name:    "valid: npm",
			eco:     ecosystem.NPM,
			wantErr: nil,
		},
		{
			name:    "valid: PyPI",
			eco:     ecosystem.PyPI,
			wantErr: nil,
		},
		{
			name:    "valid: Go",
			eco:     ecosystem.Go,
			wantErr: nil,
		},
		{
			name:    "valid: GitHub Actions",
			eco:     ecosystem.GitHubActions,
			wantErr: nil,
		},
		{
			name:    "invalid: unknown",
			eco:     ecosystem.Ecosystem("Unknown"),
			wantErr: ecosystem.ErrInvalidEcosystem,
		},
		{
			name:    "invalid: empty",
			eco:     ecosystem.Ecosystem(""),
			wantErr: ecosystem.ErrInvalidEcosystem,
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
		want    []ecosystem.Ecosystem
		wantErr error
	}{
		{
			name:    "single ecosystem",
			input:   "npm",
			want:    []ecosystem.Ecosystem{ecosystem.NPM},
			wantErr: nil,
		},
		{
			name:    "multiple ecosystems",
			input:   "npm,PyPI,Go",
			want:    []ecosystem.Ecosystem{ecosystem.NPM, ecosystem.PyPI, ecosystem.Go},
			wantErr: nil,
		},
		{
			name:    "ecosystems with spaces",
			input:   "GitHub Actions,Red Hat",
			want:    []ecosystem.Ecosystem{ecosystem.GitHubActions, ecosystem.RedHat},
			wantErr: nil,
		},
		{
			name:    "ecosystems with trimming",
			input:   " npm , PyPI , Go ",
			want:    []ecosystem.Ecosystem{ecosystem.NPM, ecosystem.PyPI, ecosystem.Go},
			wantErr: nil,
		},
		{
			name:    "empty string",
			input:   "",
			want:    []ecosystem.Ecosystem{},
			wantErr: nil,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			want:    []ecosystem.Ecosystem{},
			wantErr: nil,
		},
		{
			name:    "invalid ecosystem",
			input:   "npm,InvalidEco,PyPI",
			want:    nil,
			wantErr: ecosystem.ErrInvalidEcosystem,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecosystem.ParseEcosystems(tt.input)
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
