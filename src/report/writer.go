package report

import (
	"context"
	"fmt"
	"os"
)

// Writer handles writing reports to files.
type Writer struct {
	mdFormatter   *MarkdownFormatter
	csvFormatter  *CSVFormatter
	jsonlFormatter *JSONLFormatter
}

// NewWriter creates a new report writer.
func NewWriter() *Writer {
	return &Writer{
		mdFormatter:   NewMarkdownFormatter(),
		csvFormatter:  NewCSVFormatter(),
		jsonlFormatter: NewJSONLFormatter(),
	}
}

// WriteMarkdown writes vulnerability entries to a Markdown file.
func (w *Writer) WriteMarkdown(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := w.mdFormatter.Format(entries)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}
	return nil
}

// WriteCSV writes vulnerability entries to a CSV file.
func (w *Writer) WriteCSV(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := w.csvFormatter.Format(entries)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write csv: %w", err)
	}
	return nil
}

// WriteJSONL writes vulnerability entries to a JSONL file.
func (w *Writer) WriteJSONL(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := w.jsonlFormatter.Format(entries)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	return nil
}
