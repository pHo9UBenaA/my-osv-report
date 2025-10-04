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

		// Handle downloads
		if e.Downloads == 0 {
			obj["downloads"] = "NA"
		} else {
			obj["downloads"] = e.Downloads
		}

		// Handle GitHub stars
		if e.GitHubStars == 0 {
			obj["github_stars"] = "NA"
		} else {
			obj["github_stars"] = e.GitHubStars
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

		// Handle severity
		if e.Severity == "" {
			obj["severity"] = "NA"
		} else {
			obj["severity"] = e.Severity
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
