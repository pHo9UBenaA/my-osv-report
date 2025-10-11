package ecosystem

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var ErrInvalidEcosystem = errors.New("invalid ecosystem")

// Ecosystem represents an OSV ecosystem name.
type Ecosystem string

// Supported ecosystems.
const (
	NPM           Ecosystem = "npm"
	PyPI          Ecosystem = "PyPI"
	Go            Ecosystem = "Go"
	GitHubActions Ecosystem = "GitHub Actions"
	RubyGems      Ecosystem = "RubyGems"
	RedHat        Ecosystem = "Red Hat"
	Maven         Ecosystem = "Maven"
	NuGet         Ecosystem = "NuGet"
	OSSFuzz       Ecosystem = "OSS-Fuzz"
)

const baseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// All supported ecosystems
var supportedEcosystems = []string{
	"AlmaLinux", "Alpaquita", "Alpine", "Android", "BellSoft Hardened Containers",
	"Bitnami", "Chainguard", "CRAN", "crates.io", "Debian", "Echo", "GHC", "GIT",
	"GitHub Actions", "Go", "Hackage", "Hex", "Linux", "Mageia", "Maven", "MinimOS",
	"npm", "NuGet", "openEuler", "openSUSE", "OSS-Fuzz", "Packagist", "Pub", "PyPI",
	"Red Hat", "Rocky Linux", "RubyGems", "SUSE", "SwiftURL", "Ubuntu", "Wolfi",
}

// ModifiedCSVURL returns the URL for the all.zip file of this ecosystem.
func (e Ecosystem) ModifiedCSVURL() string {
	escapedName := url.PathEscape(string(e))
	return fmt.Sprintf("%s/%s/all.zip", baseURL, escapedName)
}

// SitemapURL returns the URL for the OSV sitemap XML of this ecosystem.
func (e Ecosystem) SitemapURL() string {
	name := strings.ReplaceAll(string(e), " ", "_")
	return fmt.Sprintf("https://osv.dev/sitemap_%s.xml", name)
}

// String returns the string representation of the ecosystem.
func (e Ecosystem) String() string {
	return string(e)
}

// Validate checks if the ecosystem is valid.
func (e Ecosystem) Validate() error {
	for _, name := range supportedEcosystems {
		if Ecosystem(name) == e {
			return nil
		}
	}
	return ErrInvalidEcosystem
}

// ParseEcosystems parses a comma-separated string into a slice of Ecosystems.
func ParseEcosystems(s string) ([]Ecosystem, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []Ecosystem{}, nil
	}

	parts := strings.Split(s, ",")
	ecosystems := make([]Ecosystem, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		eco := Ecosystem(trimmed)
		if err := eco.Validate(); err != nil {
			return nil, fmt.Errorf("invalid ecosystem %q: %w", trimmed, err)
		}
		ecosystems = append(ecosystems, eco)
	}

	return ecosystems, nil
}
