package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSONLFormatter formats vulnerability entries as JSON Lines.
type JSONLFormatter struct{}

// NewJSONLFormatter creates a new JSONL formatter.
func NewJSONLFormatter() *JSONLFormatter {
	return &JSONLFormatter{}
}

// Format generates JSONL output from vulnerability entries.
func (f *JSONLFormatter) Format(entries []VulnerabilityEntry) string {
	var sb strings.Builder

	for _, e := range entries {
		obj := map[string]interface{}{
			"ecosystem":           e.Ecosystem,
			"package":             e.Package,
			"source":              e.ID,
			"published":           formatString(e.Published),
			"modified":            formatString(e.Modified),
			"severity_base_score": formatBaseScore(e.SeverityBaseScore),
			"severity_vector":     formatString(e.SeverityVector),
		}

		data, err := json.Marshal(obj)
		if err != nil {
			// Should not happen with simple map
			panic(fmt.Sprintf("marshal error: %v", err))
		}

		sb.Write(data)
		sb.WriteString("\n")
	}

	return sb.String()
}
