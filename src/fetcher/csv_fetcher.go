package fetcher

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pHo9UBenaA/osv-scraper/src/osv"
)

// CSVFetcher fetches CSV data from a URL.
type CSVFetcher struct {
	url        string
	httpClient *http.Client
}

// NewCSVFetcher creates a new CSV fetcher.
func NewCSVFetcher(url string) *CSVFetcher {
	return &CSVFetcher{
		url:        url,
		httpClient: &http.Client{},
	}
}

// Fetch downloads and parses the CSV file.
func (f *CSVFetcher) Fetch(ctx context.Context) ([]osv.Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	entries, err := osv.ParseCSV(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}

	return entries, nil
}
