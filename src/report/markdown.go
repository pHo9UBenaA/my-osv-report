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

// markdownReplacer is used to escape special Markdown characters.
var markdownReplacer = strings.NewReplacer(
	"|", "\\|",   // Pipe breaks table structure
	"*", "\\*",   // Asterisk for emphasis/bold
	"_", "\\_",   // Underscore for emphasis/bold
	"[", "\\[",   // Opening bracket for links
	"]", "\\]",   // Closing bracket for links
	"<", "\\<",   // Opening angle bracket for HTML tags
	">", "\\>",   // Closing angle bracket for HTML tags
	"`", "\\`",   // Backtick for code
	"#", "\\#",   // Hash for headers
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
	sb.WriteString("| Ecosystem | Package | Source | Download | GitHub Star | Published | Modified | Severity |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")

	// Write entries
	for _, e := range entries {
		ecosystem := escapeMarkdown(e.Ecosystem)
		pkg := escapeMarkdown(e.Package)
		id := escapeMarkdown(e.ID)
		downloads := formatInt(e.Downloads)
		stars := formatInt(e.GitHubStars)
		published := formatString(e.Published)
		modified := formatString(e.Modified)
		severity := formatString(e.Severity)

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			ecosystem, pkg, id, downloads, stars, published, modified, severity))
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
	return escapeMarkdown(val)
}

// escapeMarkdown escapes special characters that could break Markdown table formatting
// or be interpreted as Markdown syntax.
func escapeMarkdown(s string) string {
	return markdownReplacer.Replace(s)
}
