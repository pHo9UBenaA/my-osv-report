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
	AlmaLinux                  Ecosystem = "AlmaLinux"
	Alpaquita                  Ecosystem = "Alpaquita"
	Alpine                     Ecosystem = "Alpine"
	Android                    Ecosystem = "Android"
	BellSoftHardenedContainers Ecosystem = "BellSoft Hardened Containers"
	Bitnami                    Ecosystem = "Bitnami"
	Chainguard                 Ecosystem = "Chainguard"
	CRAN                       Ecosystem = "CRAN"
	CratesIO                   Ecosystem = "crates.io"
	Debian                     Ecosystem = "Debian"
	Echo                       Ecosystem = "Echo"
	GHC                        Ecosystem = "GHC"
	GIT                        Ecosystem = "GIT"
	GitHubActions              Ecosystem = "GitHub Actions"
	Go                         Ecosystem = "Go"
	Hackage                    Ecosystem = "Hackage"
	Hex                        Ecosystem = "Hex"
	Linux                      Ecosystem = "Linux"
	Mageia                     Ecosystem = "Mageia"
	Maven                      Ecosystem = "Maven"
	MinimOS                    Ecosystem = "MinimOS"
	NPM                        Ecosystem = "npm"
	NuGet                      Ecosystem = "NuGet"
	OpenEuler                  Ecosystem = "openEuler"
	OpenSUSE                   Ecosystem = "openSUSE"
	OSSFuzz                    Ecosystem = "OSS-Fuzz"
	Packagist                  Ecosystem = "Packagist"
	Pub                        Ecosystem = "Pub"
	PyPI                       Ecosystem = "PyPI"
	RedHat                     Ecosystem = "Red Hat"
	RockyLinux                 Ecosystem = "Rocky Linux"
	RubyGems                   Ecosystem = "RubyGems"
	SUSE                       Ecosystem = "SUSE"
	SwiftURL                   Ecosystem = "SwiftURL"
	Ubuntu                     Ecosystem = "Ubuntu"
	Wolfi                      Ecosystem = "Wolfi"
)

const baseURL = "https://osv-vulnerabilities.storage.googleapis.com"

var validEcosystems = map[Ecosystem]bool{
	AlmaLinux:                  true,
	Alpaquita:                  true,
	Alpine:                     true,
	Android:                    true,
	BellSoftHardenedContainers: true,
	Bitnami:                    true,
	Chainguard:                 true,
	CRAN:                       true,
	CratesIO:                   true,
	Debian:                     true,
	Echo:                       true,
	GHC:                        true,
	GIT:                        true,
	GitHubActions:              true,
	Go:                         true,
	Hackage:                    true,
	Hex:                        true,
	Linux:                      true,
	Mageia:                     true,
	Maven:                      true,
	MinimOS:                    true,
	NPM:                        true,
	NuGet:                      true,
	OpenEuler:                  true,
	OpenSUSE:                   true,
	OSSFuzz:                    true,
	Packagist:                  true,
	Pub:                        true,
	PyPI:                       true,
	RedHat:                     true,
	RockyLinux:                 true,
	RubyGems:                   true,
	SUSE:                       true,
	SwiftURL:                   true,
	Ubuntu:                     true,
	Wolfi:                      true,
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
	if !validEcosystems[e] {
		return ErrInvalidEcosystem
	}
	return nil
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
