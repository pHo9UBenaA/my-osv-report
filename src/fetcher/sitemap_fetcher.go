package fetcher

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
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

const defaultSitemapTimeout = 30 * time.Second

func newSitemapFetcher(url string, client *http.Client, cursor time.Time) *SitemapFetcher {
	if client == nil {
		client = &http.Client{Timeout: defaultSitemapTimeout}
	} else if client.Timeout == 0 {
		client.Timeout = defaultSitemapTimeout
	}

	return &SitemapFetcher{
		url:        url,
		httpClient: client,
		cursor:     cursor,
	}
}

// NewSitemapFetcher creates a new sitemap fetcher without cursor filtering.
func NewSitemapFetcher(url string) *SitemapFetcher {
	return newSitemapFetcher(url, nil, time.Time{})
}

// NewSitemapFetcherWithCursor creates a new sitemap fetcher with cursor filtering.
func NewSitemapFetcherWithCursor(url string, cursor time.Time) *SitemapFetcher {
	return newSitemapFetcher(url, nil, cursor)
}

// NewSitemapFetcherWithClient creates a new sitemap fetcher using the provided HTTP client.
func NewSitemapFetcherWithClient(url string, client *http.Client) *SitemapFetcher {
	return newSitemapFetcher(url, client, time.Time{})
}

// NewSitemapFetcherWithClientAndCursor creates a new sitemap fetcher with cursor filtering and custom client.
func NewSitemapFetcherWithClientAndCursor(url string, client *http.Client, cursor time.Time) *SitemapFetcher {
	return newSitemapFetcher(url, client, cursor)
}

// Fetch downloads and parses the sitemap XML to extract vulnerability IDs and lastmod.
func (f *SitemapFetcher) Fetch(ctx context.Context) ([]osv.Entry, error) {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
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
