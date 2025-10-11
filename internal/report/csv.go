package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"unicode"
	"unicode/utf8"
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
	header := []string{"ecosystem", "package", "source", "published", "modified", "severity_base_score", "severity_vector"}
	if err := w.Write(header); err != nil {
		return ""
	}

	// Write entries
	for _, e := range entries {
		record := []string{
			escapeCSVInjection(e.Ecosystem),
			escapeCSVInjection(e.Package),
			escapeCSVInjection(e.ID),
			escapeCSVInjection(formatString(e.Published)),
			escapeCSVInjection(formatString(e.Modified)),
			escapeCSVInjection(formatBaseScore(e.SeverityBaseScore)),
			escapeCSVInjection(formatString(e.SeverityVector)),
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

	trimmed := strings.TrimLeftFunc(s, unicode.IsSpace)
	if trimmed == "" {
		return s
	}

	first, _ := utf8.DecodeRuneInString(trimmed)
	dangerous := []rune{'=', '+', '-', '@'}
	for _, d := range dangerous {
		if first == d {
			return "'" + s
		}
	}

	return s
}
