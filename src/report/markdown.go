package report

import (
	"fmt"
	"strings"
)

// VulnerabilityEntry represents a vulnerability with metrics for reporting.
type VulnerabilityEntry struct {
	ID          string
	Ecosystem   string
	Package     string
	Downloads   int
	GitHubStars int
	Published   string
	Modified    string
	Severity    string
}

// MarkdownFormatter formats vulnerability entries as Markdown tables.
type MarkdownFormatter struct{}

// NewMarkdownFormatter creates a new Markdown formatter.
func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

// Format generates a Markdown table from vulnerability entries.
func (f *MarkdownFormatter) Format(entries []VulnerabilityEntry) string {
	var sb strings.Builder

	// Write header
	sb.WriteString("| Ecosystem | Package | Source | Download | GitHub Star | Published | Modified | Severity |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")

	// Write entries
	for _, e := range entries {
		downloads := formatInt(e.Downloads)
		stars := formatInt(e.GitHubStars)
		published := formatString(e.Published)
		modified := formatString(e.Modified)
		severity := formatString(e.Severity)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			e.Ecosystem, e.Package, e.ID, downloads, stars, published, modified, severity))
	}

	return sb.String()
}

func formatInt(val int) string {
	if val == 0 {
		return "NA"
	}
	return fmt.Sprintf("%d", val)
}

func formatString(val string) string {
	if val == "" {
		return "NA"
	}
	return val
}
