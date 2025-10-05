package report

import (
	"bytes"
	"encoding/csv"
)

// CSVFormatter formats vulnerability entries as CSV.
type CSVFormatter struct{}

// NewCSVFormatter creates a new CSV formatter.
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// Format generates CSV output from vulnerability entries.
func (f *CSVFormatter) Format(entries []VulnerabilityEntry) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write header
	header := []string{"ecosystem", "package", "source", "downloads", "github_stars", "published", "modified", "severity"}
	if err := w.Write(header); err != nil {
		return ""
	}

	// Write entries
	for _, e := range entries {
		downloads := formatInt(e.Downloads)
		stars := formatInt(e.GitHubStars)
		published := formatString(e.Published)
		modified := formatString(e.Modified)
		severity := formatString(e.Severity)

		record := []string{
			escapeCSVInjection(e.Ecosystem),
			escapeCSVInjection(e.Package),
			escapeCSVInjection(e.ID),
			escapeCSVInjection(downloads),
			escapeCSVInjection(stars),
			escapeCSVInjection(published),
			escapeCSVInjection(modified),
			escapeCSVInjection(severity),
		}
		if err := w.Write(record); err != nil {
			return ""
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return ""
	}

	return buf.String()
}

// escapeCSVInjection prevents CSV formula injection by prefixing dangerous characters with a single quote.
func escapeCSVInjection(s string) string {
	if s == "" {
		return s
	}
	// Check if the string starts with a dangerous character
	dangerous := []rune{'=', '+', '-', '@'}
	firstChar := rune(s[0])
	for _, d := range dangerous {
		if firstChar == d {
			return "'" + s
		}
	}
	return s
}
