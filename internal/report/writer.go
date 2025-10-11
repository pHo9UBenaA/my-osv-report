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

// WriteMarkdown writes vulnerability entries to a Markdown file.
func WriteMarkdown(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := FormatMarkdown(entries)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}
	return nil
}

// WriteCSV writes vulnerability entries to a CSV file.
func WriteCSV(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := FormatCSV(entries)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write csv: %w", err)
	}
	return nil
}

// WriteJSONL writes vulnerability entries to a JSONL file.
func WriteJSONL(ctx context.Context, path string, entries []VulnerabilityEntry) error {
	content := FormatJSONL(entries)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	return nil
}
