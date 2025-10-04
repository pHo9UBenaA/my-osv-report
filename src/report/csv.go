package report

import (
	"fmt"
	"strings"
)

// CSVFormatter formats vulnerability entries as CSV.
type CSVFormatter struct{}

// NewCSVFormatter creates a new CSV formatter.
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// Format generates CSV output from vulnerability entries.
func (f *CSVFormatter) Format(entries []VulnerabilityEntry) string {
	var sb strings.Builder

	// Write header
	sb.WriteString("ecosystem,package,source,downloads,github_stars,published,modified,severity\n")

	// Write entries
	for _, e := range entries {
		downloads := formatInt(e.Downloads)
		stars := formatInt(e.GitHubStars)
		published := formatString(e.Published)
		modified := formatString(e.Modified)
		severity := formatString(e.Severity)

		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.Ecosystem, e.Package, e.ID, downloads, stars, published, modified, severity))
	}

	return sb.String()
}
