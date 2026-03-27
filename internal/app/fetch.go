package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/internal/config"
	"github.com/pHo9UBenaA/osv-scraper/internal/model"
	"github.com/pHo9UBenaA/osv-scraper/internal/osv"
	"github.com/pHo9UBenaA/osv-scraper/internal/store"
)

// Client defines the interface for fetching vulnerability data.
type Client interface {
	GetVulnerability(ctx context.Context, id string) (*model.Vulnerability, error)
}

// Fetch retrieves vulnerability data from OSV API for configured ecosystems.
func Fetch(ctx context.Context, cfg *config.Config, st *store.Store) error {
	if len(cfg.Ecosystems) == 0 {
		slog.Warn("no ecosystems configured, set OSV_ECOSYSTEMS environment variable")
		return nil
	}

	slog.Info("starting vulnerability fetch", "ecosystems", cfg.Ecosystems)

	client := osv.NewClientWithOptions(config.APIBaseURL, config.RateLimit, config.HTTPTimeout)
	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	var errs []error
	for _, eco := range cfg.Ecosystems {
		if err := processEcosystem(ctx, eco, st, client, cfg); err != nil {
			slog.Error("failed to process ecosystem", "ecosystem", eco, "error", err)
			errs = append(errs, err)
			continue
		}
	}

	if err := st.DeleteVulnerabilitiesOlderThan(ctx, retentionCutoff); err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}
	slog.Info("deleted old data", "cutoff", retentionCutoff)

	if len(errs) > 0 {
		return fmt.Errorf("some ecosystems failed to process: %w", errors.Join(errs...))
	}

	slog.Info("completed vulnerability fetch")
	return nil
}

func processEcosystem(ctx context.Context, eco model.Ecosystem, st *store.Store, client Client, cfg *config.Config) error {
	source := eco.String()
	slog.Info("processing ecosystem", "ecosystem", source)

	lastCursor, err := st.GetCursor(ctx, source)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lastCursor = time.Time{}
			slog.Info("no cursor found, starting from beginning", "ecosystem", source)
		} else {
			return fmt.Errorf("get cursor for %s: %w", source, err)
		}
	} else {
		slog.Info("resuming from cursor", "ecosystem", source, "cursor", lastCursor)
	}

	sitemapFetcher := osv.NewSitemapFetcher(eco.SitemapURL(), osv.WithSitemapCursor(lastCursor))
	entries, err := sitemapFetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch sitemap: %w", err)
	}

	slog.Info("fetched entries from sitemap", "ecosystem", source, "count", len(entries))

	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	retentionFiltered := model.FilterByCursor(entries, retentionCutoff)
	slog.Info("filtered by retention", "ecosystem", source, "count", len(retentionFiltered), "cutoff", retentionCutoff)

	if len(retentionFiltered) == 0 {
		slog.Info("no new entries to process", "ecosystem", source)
		return nil
	}

	for i := 0; i < len(retentionFiltered); i += config.BatchSize {
		end := i + config.BatchSize
		if end > len(retentionFiltered) {
			end = len(retentionFiltered)
		}

		batch := retentionFiltered[i:end]
		slog.Info("processing batch", "ecosystem", source, "batchStart", i, "batchEnd", end, "total", len(retentionFiltered))

		if err := processEntriesParallel(ctx, client, st, batch, config.MaxConcurrency); err != nil {
			return fmt.Errorf("process batch: %w", err)
		}
	}

	latestModified := model.MaxModified(retentionFiltered)
	if err := st.SaveCursor(ctx, source, latestModified); err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}

	slog.Info("completed ecosystem", "ecosystem", source, "processed", len(retentionFiltered), "cursor", latestModified)
	return nil
}
