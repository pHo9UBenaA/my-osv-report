package osv

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sync/errgroup"
)

// VulnerabilityStore defines the interface for storing vulnerability data.
type VulnerabilityStore interface {
	SaveVulnerability(ctx context.Context, vuln *Vulnerability) error
	SaveAffected(ctx context.Context, vulnID, ecosystem, pkg string) error
	SaveTombstone(ctx context.Context, id string) error
}

// Scraper coordinates fetching and storing vulnerability data.
type Scraper struct {
	client *Client
	store  VulnerabilityStore
}

// NewScraper creates a new scraper instance.
func NewScraper(client *Client, store VulnerabilityStore) *Scraper {
	return &Scraper{
		client: client,
		store:  store,
	}
}

// ProcessEntries fetches vulnerabilities for each entry and stores them.
func (s *Scraper) ProcessEntries(ctx context.Context, entries []Entry) error {
	for _, entry := range entries {
		if err := s.processEntry(ctx, entry); err != nil {
			return fmt.Errorf("process entry %s: %w", entry.ID, err)
		}
	}
	return nil
}

// ProcessEntriesParallel fetches vulnerabilities in parallel with controlled concurrency.
func (s *Scraper) ProcessEntriesParallel(ctx context.Context, entries []Entry, maxConcurrency int) error {
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, maxConcurrency)

	for _, entry := range entries {
		entry := entry // capture loop variable
		g.Go(func() error {
			sem <- struct{}{}        // acquire semaphore
			defer func() { <-sem }() // release semaphore

			return s.processEntry(ctx, entry)
		})
	}

	return g.Wait()
}

func (s *Scraper) processEntry(ctx context.Context, entry Entry) error {
	vuln, err := s.client.GetVulnerability(ctx, entry.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.store.SaveTombstone(ctx, entry.ID)
		}
		return fmt.Errorf("get vulnerability: %w", err)
	}

	if err := s.store.SaveVulnerability(ctx, vuln); err != nil {
		return fmt.Errorf("save vulnerability: %w", err)
	}

	for _, affected := range vuln.Affected {
		if err := s.store.SaveAffected(ctx, vuln.ID, affected.Package.Ecosystem, affected.Package.Name); err != nil {
			return fmt.Errorf("save affected: %w", err)
		}
	}

	return nil
}
