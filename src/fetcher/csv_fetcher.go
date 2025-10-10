package fetcher

import (
	"bytes"
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
		httpClient: NewHTTPClient(),
	}
}

// Fetch downloads and parses the CSV file.
func (f *CSVFetcher) Fetch(ctx context.Context) ([]osv.Entry, error) {
	body, err := doHTTPGet(ctx, f.httpClient, f.url)
	if err != nil {
		return nil, err
	}

	entries, err := osv.ParseCSV(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}

	return entries, nil
}
