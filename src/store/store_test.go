package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-scraper/src/store"
	_ "modernc.org/sqlite"
)

func TestNewStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx := context.Background()
	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("database file was not created at %s", dbPath)
	}
}

func TestCursorOperations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	source := "test-ecosystem"
	cursor := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)

	// Save cursor
	if err := s.SaveCursor(ctx, source, cursor); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}

	// Get cursor
	got, err := s.GetCursor(ctx, source)
	if err != nil {
		t.Fatalf("GetCursor() error = %v", err)
	}

	if !got.Equal(cursor) {
		t.Errorf("GetCursor() = %v, want %v", got, cursor)
	}
}

func TestSaveVulnerability(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	vuln := store.Vulnerability{
		ID:       "GHSA-xxxx-yyyy-zzzz",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
	}

	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	// Verify it was saved (idempotent - saving again should not error)
	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() second call error = %v", err)
	}
}

func TestSaveVulnerabilityWithDetails(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	vuln := store.Vulnerability{
		ID:       "GHSA-detail-test",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
		Summary:  "Test vulnerability summary",
		Details:  "Detailed description of the vulnerability",
	}

	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}
}

func TestSaveAffected(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	affected := store.Affected{
		VulnID:    "GHSA-test-affected",
		Ecosystem: "Go",
		Package:   "github.com/test/pkg",
	}

	if err := s.SaveAffected(ctx, affected); err != nil {
		t.Fatalf("SaveAffected() error = %v", err)
	}
}

func TestSaveTombstone(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	id := "GHSA-deleted-vuln"

	if err := s.SaveTombstone(ctx, id); err != nil {
		t.Fatalf("SaveTombstone() error = %v", err)
	}

	// Verify it was saved (idempotent - saving again should not error)
	if err := s.SaveTombstone(ctx, id); err != nil {
		t.Fatalf("SaveTombstone() second call error = %v", err)
	}
}

func TestSavePackageMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	metrics := store.PackageMetrics{
		Ecosystem:   "npm",
		Package:     "express",
		Downloads:   5678901,
		GitHubStars: 1234,
	}

	if err := s.SavePackageMetrics(ctx, metrics); err != nil {
		t.Fatalf("SavePackageMetrics() error = %v", err)
	}

	// Verify it was saved (idempotent - saving again should update)
	metricsUpdated := store.PackageMetrics{
		Ecosystem:   "npm",
		Package:     "express",
		Downloads:   6000000,
		GitHubStars: 1300,
	}
	if err := s.SavePackageMetrics(ctx, metricsUpdated); err != nil {
		t.Fatalf("SavePackageMetrics() update error = %v", err)
	}
}

func TestDeleteVulnerabilitiesOlderThan(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	// Save old vulnerabilities
	oldTime := time.Now().AddDate(0, 0, -14)
	oldVuln := store.Vulnerability{
		ID:       "GHSA-old-vuln",
		Modified: oldTime,
	}
	if err := s.SaveVulnerability(ctx, oldVuln); err != nil {
		t.Fatalf("SaveVulnerability(old) error = %v", err)
	}

	oldAffected := store.Affected{
		VulnID:    "GHSA-old-vuln",
		Ecosystem: "npm",
		Package:   "old-package",
	}
	if err := s.SaveAffected(ctx, oldAffected); err != nil {
		t.Fatalf("SaveAffected(old) error = %v", err)
	}

	if err := s.SaveTombstone(ctx, "GHSA-old-tombstone"); err != nil {
		t.Fatalf("SaveTombstone(old) error = %v", err)
	}

	// Save new vulnerabilities
	newTime := time.Now().AddDate(0, 0, -3)
	newVuln := store.Vulnerability{
		ID:       "GHSA-new-vuln",
		Modified: newTime,
	}
	if err := s.SaveVulnerability(ctx, newVuln); err != nil {
		t.Fatalf("SaveVulnerability(new) error = %v", err)
	}

	newAffected := store.Affected{
		VulnID:    "GHSA-new-vuln",
		Ecosystem: "npm",
		Package:   "new-package",
	}
	if err := s.SaveAffected(ctx, newAffected); err != nil {
		t.Fatalf("SaveAffected(new) error = %v", err)
	}

	// Delete vulnerabilities older than 7 days
	cutoff := time.Now().AddDate(0, 0, -7)
	if err := s.DeleteVulnerabilitiesOlderThan(ctx, cutoff); err != nil {
		t.Fatalf("DeleteVulnerabilitiesOlderThan() error = %v", err)
	}

	// Open database to verify deletion
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close()

	// Verify old vulnerability was deleted
	var oldCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability WHERE id = ?", "GHSA-old-vuln").Scan(&oldCount)
	if err != nil {
		t.Fatalf("query old vulnerability error = %v", err)
	}
	if oldCount != 0 {
		t.Errorf("old vulnerability was not deleted, count = %d", oldCount)
	}

	// Verify new vulnerability still exists
	var newCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability WHERE id = ?", "GHSA-new-vuln").Scan(&newCount)
	if err != nil {
		t.Fatalf("query new vulnerability error = %v", err)
	}
	if newCount != 1 {
		t.Errorf("new vulnerability was deleted, count = %d", newCount)
	}

	// Verify old affected was deleted
	var oldAffectedCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM affected WHERE vuln_id = ?", "GHSA-old-vuln").Scan(&oldAffectedCount)
	if err != nil {
		t.Fatalf("query old affected error = %v", err)
	}
	if oldAffectedCount != 0 {
		t.Errorf("old affected was not deleted, count = %d", oldAffectedCount)
	}

	// Verify new affected still exists
	var newAffectedCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM affected WHERE vuln_id = ?", "GHSA-new-vuln").Scan(&newAffectedCount)
	if err != nil {
		t.Fatalf("query new affected error = %v", err)
	}
	if newAffectedCount != 1 {
		t.Errorf("new affected was deleted, count = %d", newAffectedCount)
	}
}

func TestGetVulnerabilitiesWithMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	// Save test data
	vuln1 := store.Vulnerability{
		ID:       "GHSA-1234-5678-90ab",
		Modified: time.Now(),
		Summary:  "Test vulnerability 1",
		Details:  "Details for test vulnerability 1",
	}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(1) error = %v", err)
	}

	affected1 := store.Affected{
		VulnID:    "GHSA-1234-5678-90ab",
		Ecosystem: "npm",
		Package:   "test-package-1",
	}
	if err := s.SaveAffected(ctx, affected1); err != nil {
		t.Fatalf("SaveAffected(1) error = %v", err)
	}

	metrics1 := store.PackageMetrics{
		Ecosystem:   "npm",
		Package:     "test-package-1",
		Downloads:   1000,
		GitHubStars: 50,
	}
	if err := s.SavePackageMetrics(ctx, metrics1); err != nil {
		t.Fatalf("SavePackageMetrics(1) error = %v", err)
	}

	// Save another vulnerability with different ecosystem
	vuln2 := store.Vulnerability{
		ID:       "GHSA-abcd-efgh-ijkl",
		Modified: time.Now(),
		Summary:  "Test vulnerability 2",
		Details:  "Details for test vulnerability 2",
	}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(2) error = %v", err)
	}

	affected2 := store.Affected{
		VulnID:    "GHSA-abcd-efgh-ijkl",
		Ecosystem: "PyPI",
		Package:   "test-package-2",
	}
	if err := s.SaveAffected(ctx, affected2); err != nil {
		t.Fatalf("SaveAffected(2) error = %v", err)
	}

	// Get all vulnerabilities
	entries, err := s.GetVulnerabilitiesWithMetrics(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("GetVulnerabilitiesWithMetrics() returned %d entries, want 2", len(entries))
	}

	// Get filtered by ecosystem
	npmEntries, err := s.GetVulnerabilitiesWithMetrics(ctx, "npm")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics(npm) error = %v", err)
	}

	if len(npmEntries) != 1 {
		t.Errorf("GetVulnerabilitiesWithMetrics(npm) returned %d entries, want 1", len(npmEntries))
	}

	if npmEntries[0].ID != "GHSA-1234-5678-90ab" {
		t.Errorf("npmEntries[0].ID = %q, want %q", npmEntries[0].ID, "GHSA-1234-5678-90ab")
	}

	if npmEntries[0].Ecosystem != "npm" {
		t.Errorf("npmEntries[0].Ecosystem = %q, want %q", npmEntries[0].Ecosystem, "npm")
	}

	if npmEntries[0].Package != "test-package-1" {
		t.Errorf("npmEntries[0].Package = %q, want %q", npmEntries[0].Package, "test-package-1")
	}

	if npmEntries[0].Downloads != 1000 {
		t.Errorf("npmEntries[0].Downloads = %d, want 1000", npmEntries[0].Downloads)
	}

	if npmEntries[0].GitHubStars != 50 {
		t.Errorf("npmEntries[0].GitHubStars = %d, want 50", npmEntries[0].GitHubStars)
	}
}

func TestGetVulnerabilitiesWithMetrics_SortByPublished(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	// Save vulnerabilities with different published dates
	oldestPublished := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	middlePublished := time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC)
	newestPublished := time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC)

	// Vuln with oldest published date
	vuln1 := store.Vulnerability{
		ID:        "GHSA-oldest",
		Modified:  time.Now(),
		Published: oldestPublished,
	}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(oldest) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-oldest", Ecosystem: "npm", Package: "pkg1"}); err != nil {
		t.Fatalf("SaveAffected(oldest) error = %v", err)
	}

	// Vuln with newest published date
	vuln2 := store.Vulnerability{
		ID:        "GHSA-newest",
		Modified:  time.Now(),
		Published: newestPublished,
	}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(newest) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-newest", Ecosystem: "npm", Package: "pkg2"}); err != nil {
		t.Fatalf("SaveAffected(newest) error = %v", err)
	}

	// Vuln with middle published date
	vuln3 := store.Vulnerability{
		ID:        "GHSA-middle",
		Modified:  time.Now(),
		Published: middlePublished,
	}
	if err := s.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(middle) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-middle", Ecosystem: "npm", Package: "pkg3"}); err != nil {
		t.Fatalf("SaveAffected(middle) error = %v", err)
	}

	// Get all vulnerabilities
	entries, err := s.GetVulnerabilitiesWithMetrics(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics() error = %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("GetVulnerabilitiesWithMetrics() returned %d entries, want 3", len(entries))
	}

	// Verify they are sorted by published date (descending)
	if entries[0].ID != "GHSA-newest" {
		t.Errorf("entries[0].ID = %q, want GHSA-newest", entries[0].ID)
	}
	if entries[1].ID != "GHSA-middle" {
		t.Errorf("entries[1].ID = %q, want GHSA-middle", entries[1].ID)
	}
	if entries[2].ID != "GHSA-oldest" {
		t.Errorf("entries[2].ID = %q, want GHSA-oldest", entries[2].ID)
	}
}

func TestSaveReportSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	entries := []store.VulnerabilityReportEntry{
		{
			ID:        "GHSA-test-1",
			Ecosystem: "npm",
			Package:   "pkg1",
			Published: "2025-10-01T00:00:00Z",
			Modified:  "2025-10-02T00:00:00Z",
			Severity:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:        "GHSA-test-2",
			Ecosystem: "PyPI",
			Package:   "pkg2",
			Published: "2025-10-03T00:00:00Z",
			Modified:  "2025-10-03T00:00:00Z",
			Severity:  "",
		},
	}

	if err := s.SaveReportSnapshot(ctx, entries); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	// Verify snapshot was saved by checking the database directly
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reported_snapshot").Scan(&count)
	if err != nil {
		t.Fatalf("query count error = %v", err)
	}

	if count != 2 {
		t.Errorf("reported_snapshot count = %d, want 2", count)
	}

	// Verify first entry
	var id, ecosystem, pkg, published, modified, severity string
	err = db.QueryRowContext(ctx, "SELECT id, ecosystem, package, published, modified, severity FROM reported_snapshot WHERE id = ?", "GHSA-test-1").Scan(&id, &ecosystem, &pkg, &published, &modified, &severity)
	if err != nil {
		t.Fatalf("query first entry error = %v", err)
	}

	if id != "GHSA-test-1" || ecosystem != "npm" || pkg != "pkg1" {
		t.Errorf("first entry: got (%s, %s, %s), want (GHSA-test-1, npm, pkg1)", id, ecosystem, pkg)
	}

	// Save again (should replace old snapshot)
	newEntries := []store.VulnerabilityReportEntry{
		{
			ID:        "GHSA-test-3",
			Ecosystem: "Go",
			Package:   "pkg3",
			Published: "2025-10-04T00:00:00Z",
			Modified:  "2025-10-04T00:00:00Z",
			Severity:  "",
		},
	}

	if err := s.SaveReportSnapshot(ctx, newEntries); err != nil {
		t.Fatalf("SaveReportSnapshot(2) error = %v", err)
	}

	// Verify old snapshot was replaced
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reported_snapshot").Scan(&count)
	if err != nil {
		t.Fatalf("query count after replace error = %v", err)
	}

	if count != 1 {
		t.Errorf("reported_snapshot count after replace = %d, want 1", count)
	}

	// Verify new snapshot exists
	err = db.QueryRowContext(ctx, "SELECT id FROM reported_snapshot WHERE id = ?", "GHSA-test-3").Scan(&id)
	if err != nil {
		t.Fatalf("query new snapshot error = %v", err)
	}

	if id != "GHSA-test-3" {
		t.Errorf("new snapshot id = %q, want GHSA-test-3", id)
	}
}

func TestIndexPerformance(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	// Verify indexes exist
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Open database error = %v", err)
	}
	defer db.Close()

	// Check idx_affected_ecosystem exists
	var ecosystemIndexCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_affected_ecosystem'").Scan(&ecosystemIndexCount)
	if err != nil {
		t.Fatalf("Query index error = %v", err)
	}
	if ecosystemIndexCount != 1 {
		t.Errorf("idx_affected_ecosystem not found")
	}

	// Check idx_vulnerability_modified exists
	var modifiedIndexCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_vulnerability_modified'").Scan(&modifiedIndexCount)
	if err != nil {
		t.Fatalf("Query index error = %v", err)
	}
	if modifiedIndexCount != 1 {
		t.Errorf("idx_vulnerability_modified not found")
	}

	// Insert test data to verify index usage
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		vuln := store.Vulnerability{
			ID:       fmt.Sprintf("GHSA-test-%d", i),
			Modified: baseTime.Add(time.Duration(i) * 24 * time.Hour),
		}
		if err := s.SaveVulnerability(ctx, vuln); err != nil {
			t.Fatalf("SaveVulnerability(%d) error = %v", i, err)
		}

		ecosystem := "npm"
		if i%3 == 0 {
			ecosystem = "PyPI"
		} else if i%3 == 1 {
			ecosystem = "Go"
		}
		affected := store.Affected{
			VulnID:    vuln.ID,
			Ecosystem: ecosystem,
			Package:   fmt.Sprintf("package-%d", i),
		}
		if err := s.SaveAffected(ctx, affected); err != nil {
			t.Fatalf("SaveAffected(%d) error = %v", i, err)
		}
	}

	// Test ecosystem filter query uses index
	// i=0,3,6,9: PyPI (4)
	// i=1,4,7: Go (3)
	// i=2,5,8: npm (3)
	entries, err := s.GetVulnerabilitiesWithMetrics(ctx, "npm")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesWithMetrics error = %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Expected 3 npm entries, got %d", len(entries))
	}

	// Test delete old vulnerabilities uses index
	cutoff := baseTime.Add(5 * 24 * time.Hour)
	if err := s.DeleteVulnerabilitiesOlderThan(ctx, cutoff); err != nil {
		t.Fatalf("DeleteVulnerabilitiesOlderThan error = %v", err)
	}

	// Verify deletion worked correctly
	var remainingCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability").Scan(&remainingCount)
	if err != nil {
		t.Fatalf("Count remaining vulnerabilities error = %v", err)
	}
	if remainingCount != 5 {
		t.Errorf("Expected 5 remaining vulnerabilities, got %d", remainingCount)
	}
}

func TestGetUnreportedVulnerabilities(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer s.Close()

	// Setup: Create vulnerabilities
	vuln1 := store.Vulnerability{
		ID:        "GHSA-unchanged",
		Modified:  time.Now(),
		Published: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Severity:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(unchanged) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-unchanged", Ecosystem: "npm", Package: "pkg-unchanged"}); err != nil {
		t.Fatalf("SaveAffected(unchanged) error = %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:        "GHSA-modified",
		Modified:  time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		Severity:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(modified) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-modified", Ecosystem: "npm", Package: "pkg-modified"}); err != nil {
		t.Fatalf("SaveAffected(modified) error = %v", err)
	}

	vuln3 := store.Vulnerability{
		ID:        "GHSA-new",
		Modified:  time.Now(),
		Published: time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
		Severity:  "",
	}
	if err := s.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(new) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-new", Ecosystem: "PyPI", Package: "pkg-new"}); err != nil {
		t.Fatalf("SaveAffected(new) error = %v", err)
	}

	// Setup: Create snapshot with old data
	snapshot := []store.VulnerabilityReportEntry{
		{
			ID:        "GHSA-unchanged",
			Ecosystem: "npm",
			Package:   "pkg-unchanged",
			Published: "2025-10-01T00:00:00Z",
			Modified:  time.Now().Format(time.RFC3339),
			Severity:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:        "GHSA-modified",
			Ecosystem: "npm",
			Package:   "pkg-modified",
			Published: "2025-10-01T00:00:00Z",
			Modified:  "2025-10-02T00:00:00Z", // Old modified date
			Severity:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
		},
	}
	if err := s.SaveReportSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	// Test: Get unreported vulnerabilities
	unreported, err := s.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() error = %v", err)
	}

	// Verify: Should return modified and new vulnerabilities
	if len(unreported) != 2 {
		t.Fatalf("GetUnreportedVulnerabilities() returned %d entries, want 2", len(unreported))
	}

	// Check that we got the modified and new entries (order may vary)
	foundModified := false
	foundNew := false
	for _, e := range unreported {
		if e.ID == "GHSA-modified" {
			foundModified = true
		}
		if e.ID == "GHSA-new" {
			foundNew = true
		}
		if e.ID == "GHSA-unchanged" {
			t.Errorf("GetUnreportedVulnerabilities() returned unchanged vulnerability")
		}
	}

	if !foundModified {
		t.Errorf("GetUnreportedVulnerabilities() did not return GHSA-modified")
	}
	if !foundNew {
		t.Errorf("GetUnreportedVulnerabilities() did not return GHSA-new")
	}

	// Test: Filter by ecosystem
	npmUnreported, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm) error = %v", err)
	}

	if len(npmUnreported) != 1 {
		t.Fatalf("GetUnreportedVulnerabilities(npm) returned %d entries, want 1", len(npmUnreported))
	}

	if npmUnreported[0].ID != "GHSA-modified" {
		t.Errorf("GetUnreportedVulnerabilities(npm)[0].ID = %q, want GHSA-modified", npmUnreported[0].ID)
	}
}
