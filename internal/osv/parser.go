package osv

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

var errInvalidLine = fmt.Errorf("invalid line format")

// Entry represents a vulnerability entry with ID and modified timestamp.
type Entry struct {
	ID       string
	Modified time.Time
}

// ParseCSV parses CSV data from reader and returns all entries.
func ParseCSV(r io.Reader) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		id, modified, err := ParseLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse line %q: %w", line, err)
		}

		entries = append(entries, Entry{
			ID:       id,
			Modified: modified,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan csv: %w", err)
	}

	return entries, nil
}

// FilterByCursor filters entries to only include those modified after the cursor time.
func FilterByCursor(entries []Entry, cursor time.Time) []Entry {
	var filtered []Entry
	for _, e := range entries {
		if e.Modified.After(cursor) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// ParseLine parses a single CSV line containing vulnerability ID and modified timestamp.
func ParseLine(line string) (string, time.Time, error) {
	parts := strings.Split(line, ",")
	if len(parts) != 2 {
		return "", time.Time{}, errInvalidLine
	}

	id := parts[0]
	modifiedStr := parts[1]

	modified, err := time.Parse(time.RFC3339, modifiedStr)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse modified timestamp: %w", err)
	}

	return id, modified, nil
}
