package fetcher

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/osv"
)

// SitemapURL represents a URL entry in the sitemap.
type SitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod"`
}

// SitemapURLSet represents the root element of a sitemap XML.
type SitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []SitemapURL `xml:"url"`
}

// SitemapFetcher fetches vulnerability list from OSV sitemap.
type SitemapFetcher struct {
	url        string
	httpClient *http.Client
	cursor     time.Time
}

// SitemapFetcherOption configures a SitemapFetcher.
type SitemapFetcherOption func(*SitemapFetcher)

// WithHTTPClient sets a custom HTTP client on the sitemap fetcher.
func WithHTTPClient(client *http.Client) SitemapFetcherOption {
	return func(f *SitemapFetcher) {
		f.httpClient = client
	}
}

// WithCursor sets the cursor used to filter sitemap entries.
func WithCursor(cursor time.Time) SitemapFetcherOption {
	return func(f *SitemapFetcher) {
		f.cursor = cursor
	}
}

// NewSitemapFetcher creates a new sitemap fetcher with optional configuration.
func NewSitemapFetcher(url string, opts ...SitemapFetcherOption) *SitemapFetcher {
	f := &SitemapFetcher{
		url:        url,
		httpClient: NewHTTPClient(),
	}

	for _, opt := range opts {
		opt(f)
	}

	if f.httpClient == nil {
		f.httpClient = NewHTTPClient()
	} else if f.httpClient.Timeout == 0 {
		f.httpClient.Timeout = defaultHTTPTimeout
	}

	return f
}

// Fetch downloads and parses the sitemap XML to extract vulnerability IDs and lastmod.
func (f *SitemapFetcher) Fetch(ctx context.Context) ([]osv.Entry, error) {
	body, err := doHTTPGet(ctx, f.httpClient, f.url)
	if err != nil {
		return nil, err
	}

	return f.parseSitemap(body)
}

func (f *SitemapFetcher) parseSitemap(xmlData []byte) ([]osv.Entry, error) {
	var urlset SitemapURLSet
	if err := xml.Unmarshal(xmlData, &urlset); err != nil {
		return nil, fmt.Errorf("unmarshal sitemap: %w", err)
	}

	// Extract vulnerability ID from URL
	re := regexp.MustCompile(`/vulnerability/([A-Za-z0-9]+-[A-Za-z0-9-]+)`)

	var entries []osv.Entry
	for _, u := range urlset.URLs {
		// Parse lastmod
		lastmod, err := time.Parse(time.RFC3339, u.LastMod)
		if err != nil {
			// Skip entries with invalid lastmod
			continue
		}

		// Filter by cursor
		if !f.cursor.IsZero() && !lastmod.After(f.cursor) {
			continue
		}

		// Extract vulnerability ID from URL
		matches := re.FindStringSubmatch(u.Loc)
		if len(matches) < 2 {
			continue
		}

		id := matches[1]
		entries = append(entries, osv.Entry{
			ID:       id,
			Modified: lastmod,
		})
	}

	return entries, nil
}

// HTTPClientTimeout returns the configured HTTP client timeout.
func (f *SitemapFetcher) HTTPClientTimeout() time.Duration {
	if f.httpClient == nil {
		return 0
	}

	return f.httpClient.Timeout
}
