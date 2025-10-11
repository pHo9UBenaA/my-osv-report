package severity

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
)

// ExtractFromOSV extracts severity vector information and optional base score from OSV severity data.
// It returns the computed base score (if derivable), the vector string, and an error when parsing fails.
func ExtractFromOSV(severities []osv.Severity) (*float64, string, error) {
	if len(severities) == 0 {
		return nil, "", nil
	}

	vector := strings.TrimSpace(severities[0].Score)
	if vector == "" {
		return nil, "", nil
	}

	base, err := ParseVector(vector)
	if err != nil {
		return nil, vector, err
	}

	return &base, vector, nil
}

// ParseVector parses a severity vector string and returns the numeric base score when possible.
// Supported formats currently include CVSS v3.x vectors and plain numeric scores.
func ParseVector(vector string) (float64, error) {
	if strings.HasPrefix(vector, "CVSS:3.") {
		return computeCVSS3BaseScore(vector)
	}

	return strconv.ParseFloat(vector, 64)
}

func computeCVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid CVSS vector")
	}
	if !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("unsupported CVSS version")
	}

	metrics := make(map[string]string, len(parts)-1)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, key := range required {
		if _, ok := metrics[key]; !ok {
			return 0, fmt.Errorf("missing metric %s", key)
		}
	}

	avWeights := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acWeights := map[string]float64{"L": 0.77, "H": 0.44}
	uiWeights := map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	scopeChanged := metrics["S"] == "C"
	prWeightsUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}

	av, ok := avWeights[metrics["AV"]]
	if !ok {
		return 0, fmt.Errorf("invalid AV metric")
	}
	ac, ok := acWeights[metrics["AC"]]
	if !ok {
		return 0, fmt.Errorf("invalid AC metric")
	}
	var pr float64
	if scopeChanged {
		var okPR bool
		pr, okPR = prWeightsChanged[metrics["PR"]]
		if !okPR {
			return 0, fmt.Errorf("invalid PR metric")
		}
	} else {
		var okPR bool
		pr, okPR = prWeightsUnchanged[metrics["PR"]]
		if !okPR {
			return 0, fmt.Errorf("invalid PR metric")
		}
	}
	ui, ok := uiWeights[metrics["UI"]]
	if !ok {
		return 0, fmt.Errorf("invalid UI metric")
	}
	conf, ok := ciaWeights[metrics["C"]]
	if !ok {
		return 0, fmt.Errorf("invalid C metric")
	}
	integ, ok := ciaWeights[metrics["I"]]
	if !ok {
		return 0, fmt.Errorf("invalid I metric")
	}
	avail, ok := ciaWeights[metrics["A"]]
	if !ok {
		return 0, fmt.Errorf("invalid A metric")
	}

	exploitability := 8.22 * av * ac * pr * ui
	impactSubscore := 1 - (1-conf)*(1-integ)*(1-avail)
	if impactSubscore <= 0 {
		return 0, nil
	}

	if scopeChanged {
		impact := 7.52*(impactSubscore-0.029) - 3.25*math.Pow(impactSubscore-0.02, 15)
		impact = math.Max(impact, 0)
		return roundUp1Decimal(math.Min(1.08*(impact+exploitability), 10)), nil
	}

	impact := 6.42 * impactSubscore
	return roundUp1Decimal(math.Min(impact+exploitability, 10)), nil
}

func roundUp1Decimal(val float64) float64 {
	return math.Ceil(val*10) / 10
}
