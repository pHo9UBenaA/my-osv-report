package app

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/config"
	"github.com/pHo9UBenaA/osv-scraper/internal/fetcher"
	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
	"github.com/pHo9UBenaA/osv-scraper/internal/severity"
	"github.com/pHo9UBenaA/osv-scraper/internal/store"
)

// Fetch retrieves vulnerability data from OSV API for configured ecosystems.
func Fetch(ctx context.Context, cfg *config.Config, st *store.Store) error {
	if len(cfg.Ecosystems) == 0 {
		slog.Warn("no ecosystems configured, set OSV_ECOSYSTEMS environment variable")
		return nil
	}

	slog.Info("starting vulnerability fetch",
		"ecosystems", cfg.Ecosystems,
		"rateLimit", cfg.RateLimit,
		"maxConcurrency", cfg.MaxConcurrency,
		"batchSize", cfg.BatchSize)

	client := osv.NewClientWithOptions(cfg.APIBaseURL, cfg.RateLimit, cfg.HTTPTimeout)
	scraper := osv.NewScraper(client, &storeAdapter{st})

	var lastErr error
	for _, eco := range cfg.Ecosystems {
		if err := processEcosystem(ctx, eco, st, scraper, cfg); err != nil {
			slog.Error("failed to process ecosystem", "ecosystem", eco, "error", err)
			lastErr = err
			continue
		}
	}

	if lastErr != nil {
		return fmt.Errorf("some ecosystems failed to process: %w", lastErr)
	}

	slog.Info("completed vulnerability fetch")
	return nil
}

func processEcosystem(ctx context.Context, eco interface {
	SitemapURL() string
	String() string
}, st *store.Store, scraper *osv.Scraper, cfg *config.Config) error {
	source := eco.String()
	slog.Info("processing ecosystem", "ecosystem", source)

	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	lastCursor, err := st.GetCursor(ctx, source)
	if err != nil {
		if err == sql.ErrNoRows {
			lastCursor = time.Time{}
			slog.Info("no cursor found, starting from beginning", "ecosystem", source)
		} else {
			return fmt.Errorf("get cursor for %s: %w", source, err)
		}
	} else {
		slog.Info("resuming from cursor", "ecosystem", source, "cursor", lastCursor)
	}

	sitemapFetcher := fetcher.NewSitemapFetcher(eco.SitemapURL(), fetcher.WithCursor(lastCursor))
	entries, err := sitemapFetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch sitemap: %w", err)
	}

	slog.Info("fetched entries from sitemap", "ecosystem", source, "count", len(entries))

	retentionFiltered := osv.FilterByCursor(entries, retentionCutoff)
	slog.Info("filtered by retention", "ecosystem", source, "count", len(retentionFiltered), "cutoff", retentionCutoff)

	if len(retentionFiltered) == 0 {
		slog.Info("no new entries to process", "ecosystem", source)
		return nil
	}

	for i := 0; i < len(retentionFiltered); i += cfg.BatchSize {
		end := i + cfg.BatchSize
		if end > len(retentionFiltered) {
			end = len(retentionFiltered)
		}

		batch := retentionFiltered[i:end]
		slog.Info("processing batch", "ecosystem", source, "batchStart", i, "batchEnd", end, "total", len(retentionFiltered))

		if err := scraper.ProcessEntriesParallel(ctx, batch, cfg.MaxConcurrency); err != nil {
			return fmt.Errorf("process batch: %w", err)
		}
	}

	latestModified := retentionFiltered[len(retentionFiltered)-1].Modified
	if err := st.SaveCursor(ctx, source, latestModified); err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}

	if err := st.DeleteVulnerabilitiesOlderThan(ctx, retentionCutoff); err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}
	slog.Info("deleted old data", "ecosystem", source, "cutoff", retentionCutoff)

	slog.Info("completed ecosystem", "ecosystem", source, "processed", len(retentionFiltered), "cursor", latestModified)
	return nil
}

type storeAdapter struct {
	s *store.Store
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

	return a.s.SaveVulnerability(ctx, store.Vulnerability{
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
	return a.s.SaveAffected(ctx, store.Affected{
		VulnID:    vulnID,
		Ecosystem: ecosystem,
		Package:   pkg,
	})
}

func (a *storeAdapter) SaveTombstone(ctx context.Context, id string) error {
	return a.s.SaveTombstone(ctx, id)
}
