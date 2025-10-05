package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Vulnerability represents a vulnerability record in the database.
type Vulnerability struct {
	ID        string
	Modified  time.Time
	Published time.Time
	Summary   string
	Details   string
	Severity  string
}

// Affected represents an affected package in the database.
type Affected struct {
	VulnID    string
	Ecosystem string
	Package   string
}

// PackageMetrics represents download and popularity metrics for a package.
type PackageMetrics struct {
	Ecosystem   string
	Package     string
	Downloads   int
	GitHubStars int
}

// VulnerabilityReportEntry represents a vulnerability with metadata for reporting.
type VulnerabilityReportEntry struct {
	ID          string
	Ecosystem   string
	Package     string
	Downloads   int
	GitHubStars int
	Published   string
	Modified    string
	Severity    string
}

// Store manages database operations for the OSV scraper.
type Store struct {
	db *sql.DB
}

// NewStore creates a new store instance and initializes the database.
func NewStore(ctx context.Context, dbPath string) (*Store, error) {
	// Add pragma parameters for concurrent access support
	connStr := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool for concurrent access
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	s := &Store{db: db}

	if err := s.initSchema(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	// Enable WAL mode for concurrent write support
	_, err := s.db.ExecContext(ctx, "PRAGMA journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("enable WAL mode: %w", err)
	}

	// Set busy timeout to 5 seconds
	_, err = s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("set busy timeout: %w", err)
	}

	schema := `
		CREATE TABLE IF NOT EXISTS source_cursor (
			source TEXT PRIMARY KEY,
			cursor TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS vulnerability (
			id TEXT PRIMARY KEY,
			modified TEXT NOT NULL,
			published TEXT,
			summary TEXT,
			details TEXT,
			severity TEXT
		);

		CREATE TABLE IF NOT EXISTS tombstone (
			id TEXT PRIMARY KEY,
			deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS affected (
			vuln_id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			FOREIGN KEY (vuln_id) REFERENCES vulnerability(id),
			PRIMARY KEY (vuln_id, ecosystem, package)
		);

		CREATE TABLE IF NOT EXISTS package_metrics (
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			downloads INTEGER,
			github_stars INTEGER,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (ecosystem, package)
		);

		CREATE TABLE IF NOT EXISTS reported_snapshot (
			id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			published TEXT,
			modified TEXT,
			severity TEXT,
			PRIMARY KEY (id, ecosystem, package)
		);

		CREATE INDEX IF NOT EXISTS idx_affected_ecosystem ON affected(ecosystem);
		CREATE INDEX IF NOT EXISTS idx_vulnerability_modified ON vulnerability(modified);
	`
	_, err = s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// Migrate existing tables: add published and severity columns if they don't exist
	migrations := []string{
		"ALTER TABLE vulnerability ADD COLUMN published TEXT",
		"ALTER TABLE vulnerability ADD COLUMN severity TEXT",
	}
	for _, migration := range migrations {
		_, err = s.db.ExecContext(ctx, migration)
		// Ignore "duplicate column" errors (SQLite doesn't have IF NOT EXISTS for ALTER TABLE ADD COLUMN)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("run migration: %w", err)
		}
	}

	return nil
}

// SaveCursor saves the cursor for a given source.
func (s *Store) SaveCursor(ctx context.Context, source string, cursor time.Time) error {
	query := `
		INSERT INTO source_cursor (source, cursor)
		VALUES (?, ?)
		ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor
	`
	_, err := s.db.ExecContext(ctx, query, source, cursor.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}
	return nil
}

// GetCursor retrieves the cursor for a given source.
// Returns sql.ErrNoRows directly if no cursor exists for the source,
// allowing callers to distinguish "no cursor yet" from database errors.
func (s *Store) GetCursor(ctx context.Context, source string) (time.Time, error) {
	query := `SELECT cursor FROM source_cursor WHERE source = ?`
	var cursorStr string
	err := s.db.QueryRowContext(ctx, query, source).Scan(&cursorStr)
	if err != nil {
		// Return sql.ErrNoRows directly to allow caller to distinguish
		// "no cursor found" from actual database errors
		if err == sql.ErrNoRows {
			return time.Time{}, sql.ErrNoRows
		}
		return time.Time{}, fmt.Errorf("get cursor: %w", err)
	}

	cursor, err := time.Parse(time.RFC3339, cursorStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse cursor: %w", err)
	}

	return cursor, nil
}

// SaveVulnerability saves a vulnerability to the database.
func (s *Store) SaveVulnerability(ctx context.Context, v Vulnerability) error {
	publishedStr := ""
	if !v.Published.IsZero() {
		publishedStr = v.Published.Format(time.RFC3339)
	}

	query := `
		INSERT INTO vulnerability (id, modified, published, summary, details, severity)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			modified = excluded.modified,
			published = excluded.published,
			summary = excluded.summary,
			details = excluded.details,
			severity = excluded.severity
	`
	_, err := s.db.ExecContext(ctx, query, v.ID, v.Modified.Format(time.RFC3339), publishedStr, v.Summary, v.Details, v.Severity)
	if err != nil {
		return fmt.Errorf("save vulnerability: %w", err)
	}
	return nil
}

// SaveAffected saves an affected package record.
func (s *Store) SaveAffected(ctx context.Context, a Affected) error {
	query := `
		INSERT INTO affected (vuln_id, ecosystem, package)
		VALUES (?, ?, ?)
		ON CONFLICT(vuln_id, ecosystem, package) DO NOTHING
	`
	_, err := s.db.ExecContext(ctx, query, a.VulnID, a.Ecosystem, a.Package)
	if err != nil {
		return fmt.Errorf("save affected: %w", err)
	}
	return nil
}

// SaveTombstone records a deleted vulnerability ID.
func (s *Store) SaveTombstone(ctx context.Context, id string) error {
	query := `
		INSERT INTO tombstone (id)
		VALUES (?)
		ON CONFLICT(id) DO NOTHING
	`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("save tombstone: %w", err)
	}
	return nil
}

// SavePackageMetrics saves package download and popularity metrics.
func (s *Store) SavePackageMetrics(ctx context.Context, m PackageMetrics) error {
	query := `
		INSERT INTO package_metrics (ecosystem, package, downloads, github_stars, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(ecosystem, package) DO UPDATE SET
			downloads = excluded.downloads,
			github_stars = excluded.github_stars,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := s.db.ExecContext(ctx, query, m.Ecosystem, m.Package, m.Downloads, m.GitHubStars)
	if err != nil {
		return fmt.Errorf("save package metrics: %w", err)
	}
	return nil
}

// GetVulnerabilitiesWithMetrics retrieves vulnerabilities with metrics for reporting.
// If ecosystem is empty, returns all vulnerabilities. Otherwise, filters by ecosystem.
func (s *Store) GetVulnerabilitiesWithMetrics(ctx context.Context, ecosystem string) ([]VulnerabilityReportEntry, error) {
	query := `
		SELECT
			v.id,
			a.ecosystem,
			a.package,
			COALESCE(m.downloads, 0) as downloads,
			COALESCE(m.github_stars, 0) as github_stars,
			COALESCE(v.published, '') as published,
			v.modified,
			COALESCE(v.severity, '') as severity
		FROM vulnerability v
		INNER JOIN affected a ON v.id = a.vuln_id
		LEFT JOIN package_metrics m ON a.ecosystem = m.ecosystem AND a.package = m.package
	`

	args := []interface{}{}
	if ecosystem != "" {
		query += " WHERE a.ecosystem = ?"
		args = append(args, ecosystem)
	}

	query += " ORDER BY COALESCE(v.published, v.modified) DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var entries []VulnerabilityReportEntry
	for rows.Next() {
		var e VulnerabilityReportEntry
		if err := rows.Scan(&e.ID, &e.Ecosystem, &e.Package, &e.Downloads, &e.GitHubStars, &e.Published, &e.Modified, &e.Severity); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return entries, nil
}

// DeleteVulnerabilitiesOlderThan deletes vulnerabilities and related data older than the cutoff time.
func (s *Store) DeleteVulnerabilitiesOlderThan(ctx context.Context, cutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	cutoffStr := cutoff.Format(time.RFC3339)

	// Delete affected records for old vulnerabilities
	_, err = tx.ExecContext(ctx, `
		DELETE FROM affected WHERE vuln_id IN (
			SELECT id FROM vulnerability WHERE modified < ?
		)
	`, cutoffStr)
	if err != nil {
		return fmt.Errorf("delete old affected records: %w", err)
	}

	// Delete old vulnerabilities
	_, err = tx.ExecContext(ctx, `DELETE FROM vulnerability WHERE modified < ?`, cutoffStr)
	if err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// GetUnreportedVulnerabilities retrieves vulnerabilities that differ from the last snapshot.
// Returns vulnerabilities that are new or have changed (different modified/severity).
func (s *Store) GetUnreportedVulnerabilities(ctx context.Context, ecosystem string) ([]VulnerabilityReportEntry, error) {
	query := `
		SELECT
			v.id,
			a.ecosystem,
			a.package,
			COALESCE(m.downloads, 0) as downloads,
			COALESCE(m.github_stars, 0) as github_stars,
			COALESCE(v.published, '') as published,
			v.modified,
			COALESCE(v.severity, '') as severity
		FROM vulnerability v
		INNER JOIN affected a ON v.id = a.vuln_id
		LEFT JOIN package_metrics m ON a.ecosystem = m.ecosystem AND a.package = m.package
		LEFT JOIN reported_snapshot r ON v.id = r.id AND a.ecosystem = r.ecosystem AND a.package = r.package
		WHERE (
			r.id IS NULL
			OR r.modified != v.modified
			OR COALESCE(r.severity, '') != COALESCE(v.severity, '')
		)
	`

	args := []interface{}{}
	if ecosystem != "" {
		query += " AND a.ecosystem = ?"
		args = append(args, ecosystem)
	}

	query += " ORDER BY COALESCE(v.published, v.modified) DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query unreported vulnerabilities: %w", err)
	}
	defer rows.Close()

	var entries []VulnerabilityReportEntry
	for rows.Next() {
		var e VulnerabilityReportEntry
		if err := rows.Scan(&e.ID, &e.Ecosystem, &e.Package, &e.Downloads, &e.GitHubStars, &e.Published, &e.Modified, &e.Severity); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return entries, nil
}

// SaveReportSnapshot saves the current report snapshot, replacing any existing snapshot.
func (s *Store) SaveReportSnapshot(ctx context.Context, entries []VulnerabilityReportEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear existing snapshot
	_, err = tx.ExecContext(ctx, "DELETE FROM reported_snapshot")
	if err != nil {
		return fmt.Errorf("clear snapshot: %w", err)
	}

	// Insert new snapshot entries
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO reported_snapshot (id, ecosystem, package, published, modified, severity)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err = stmt.ExecContext(ctx, e.ID, e.Ecosystem, e.Package, e.Published, e.Modified, e.Severity)
		if err != nil {
			return fmt.Errorf("insert snapshot entry: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
