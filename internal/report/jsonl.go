package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatJSONL converts vulnerability entries to a JSONL string.
func FormatJSONL(entries []VulnerabilityEntry) string {
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
