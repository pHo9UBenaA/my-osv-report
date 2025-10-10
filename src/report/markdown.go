package report

import (
	"fmt"
	"strings"
)

// VulnerabilityEntry represents a vulnerability with metrics for reporting.
type VulnerabilityEntry struct {
	ID                string
	Ecosystem         string
	Package           string
	Published         string
	Modified          string
	SeverityBaseScore *float64
	SeverityVector    string
}

// markdownReplacer is used to escape special Markdown characters.
var markdownReplacer = strings.NewReplacer(
	"|", "\\|", // Pipe breaks table structure
	"*", "\\*", // Asterisk for emphasis/bold
	"_", "\\_", // Underscore for emphasis/bold
	"[", "\\[", // Opening bracket for links
	"]", "\\]", // Closing bracket for links
	"<", "\\<", // Opening angle bracket for HTML tags
	">", "\\>", // Closing angle bracket for HTML tags
	"`", "\\`", // Backtick for code
	"#", "\\#", // Hash for headers
	"\\", "\\\\", // Backslash itself
)

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
	sb.WriteString("| Ecosystem | Package | Source | Published | Modified | Severity: Base Score | Severity: Vector String |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")

	// Write entries
	for _, e := range entries {
		ecosystem := escapeMarkdown(e.Ecosystem)
		pkg := escapeMarkdown(e.Package)
		id := escapeMarkdown(e.ID)
		published := formatString(e.Published)
		modified := formatString(e.Modified)
		severityBase := formatBaseScore(e.SeverityBaseScore)
		severityVector := formatString(e.SeverityVector)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
			ecosystem, pkg, id, published, modified, severityBase, severityVector))
	}

	return sb.String()
}

func formatString(val string) string {
	if val == "" {
		return "NA"
	}
	return escapeMarkdown(val)
}

func formatBaseScore(val *float64) string {
	if val == nil {
		return "NA"
	}
	return fmt.Sprintf("%.1f", *val)
}

// escapeMarkdown escapes special characters that could break Markdown table formatting
// or be interpreted as Markdown syntax.
func escapeMarkdown(s string) string {
	return markdownReplacer.Replace(s)
}
