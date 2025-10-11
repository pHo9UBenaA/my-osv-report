package app

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
	"github.com/pHo9UBenaA/osv-scraper/internal/severity"
	"github.com/pHo9UBenaA/osv-scraper/internal/store"
)

// storeAdapter adapts OSV vulnerability data to store format.
type storeAdapter struct {
	st *store.Store
}

func (a *storeAdapter) SaveVulnerability(ctx context.Context, vuln *osv.Vulnerability) error {
	baseScore, vector, err := severity.ExtractFromOSV(vuln.Severity)
	if err != nil {
		slog.Debug("parse severity", "id", vuln.ID, "vector", vector, "err", err)
	}

	var base sql.NullFloat64
	if baseScore != nil {
		base = sql.NullFloat64{Float64: *baseScore, Valid: true}
	}

	return a.st.SaveVulnerability(ctx, store.Vulnerability{
		ID:                vuln.ID,
		Modified:          vuln.Modified,
		Published:         vuln.Published,
		Summary:           vuln.Summary,
		Details:           vuln.Details,
		SeverityBaseScore: base,
		SeverityVector:    vector,
	})
}

func (a *storeAdapter) SaveAffected(ctx context.Context, vulnID, ecosystem, pkg string) error {
	return a.st.SaveAffected(ctx, store.Affected{
		VulnID:    vulnID,
		Ecosystem: ecosystem,
		Package:   pkg,
	})
}

func (a *storeAdapter) SaveTombstone(ctx context.Context, id string) error {
	return a.st.SaveTombstone(ctx, id)
}
