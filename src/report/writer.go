package report

import (
	"context"
	"fmt"
	"os"
)

// formatString returns "NA" if val is empty, otherwise returns val.
func formatString(val string) string {
	if val == "" {
		return "NA"
	}
	return val
}

// formatBaseScore returns "NA" if val is nil, otherwise returns formatted float.
func formatBaseScore(val *float64) string {
	if val == nil {
		return "NA"
	}
	return fmt.Sprintf("%.1f", *val)
}

// Formatter formats vulnerability entries to a string representation.
type Formatter interface {
	Format(entries []VulnerabilityEntry) string
}

// Writer handles writing reports to files.
type Writer struct {
	mdFormatter    *MarkdownFormatter
	csvFormatter   *CSVFormatter
	jsonlFormatter *JSONLFormatter
}

// NewWriter creates a new report writer.
func NewWriter() *Writer {
	return &Writer{
		mdFormatter:    NewMarkdownFormatter(),
		csvFormatter:   NewCSVFormatter(),
		jsonlFormatter: NewJSONLFormatter(),
	}
}

func (w *Writer) write(ctx context.Context, path string, entries []VulnerabilityEntry, formatter Formatter, formatName string) error {
	content := formatter.Format(entries)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write %s: %w", formatName, err)
	}
	return nil
}

// WriteMarkdown writes vulnerability entries to a Markdown file.
func (w *Writer) WriteMarkdown(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	return w.write(ctx, path, entries, w.mdFormatter, "markdown")
}

// WriteCSV writes vulnerability entries to a CSV file.
func (w *Writer) WriteCSV(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	return w.write(ctx, path, entries, w.csvFormatter, "csv")
}

// WriteJSONL writes vulnerability entries to a JSONL file.
func (w *Writer) WriteJSONL(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	return w.write(ctx, path, entries, w.jsonlFormatter, "jsonl")
}
