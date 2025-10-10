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
			"ecosystem": e.Ecosystem,
			"package":   e.Package,
			"source":    e.ID,
		}

		// Handle published
		if e.Published == "" {
			obj["published"] = "NA"
		} else {
			obj["published"] = e.Published
		}

		// Handle modified
		if e.Modified == "" {
			obj["modified"] = "NA"
		} else {
			obj["modified"] = e.Modified
		}

		// Handle severity base score
		if e.SeverityBaseScore == nil {
			obj["severity_base_score"] = "NA"
		} else {
			obj["severity_base_score"] = formatBaseScore(e.SeverityBaseScore)
		}

		// Handle severity vector
		if e.SeverityVector == "" {
			obj["severity_vector"] = "NA"
		} else {
			obj["severity_vector"] = e.SeverityVector
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
