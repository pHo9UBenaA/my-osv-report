# OSV Scraper

A tool to fetch vulnerability information from OSV (Open Source Vulnerabilities) using sitemaps, CSV archives, and OSV API.

## Architecture

```
osv-scraper/
├── cmd/osv-scraper/     # CLI entry point
│   └── main.go
├── src/                 # Source code
│   ├── config/          # Configuration management (environment variable loading)
│   ├── ecosystem/       # Ecosystem definitions & URL mapper
│   ├── fetcher/         # Sitemap fetcher & CSV fetcher
│   ├── metrics/         # Metrics collection (GitHub, npm, PyPI)
│   ├── osv/             # OSV scraper, API client & parser
│   ├── report/          # Report output (CSV, JSONL, Markdown)
│   └── store/           # SQLite storage
└── go.mod
```

## Usage

Available Tasks

```bash
task --list
```

Build

```bash
task build
```

### Run

You can configure the application using either environment variables or a `.env` file.

#### Using .env file (recommended)

```bash
# Copy the example file and edit it
cp .env.example .env

# Edit .env to set your configuration
# Then run
task run
```

### Environment Variables

| Variable Name | Description | Default Value |
| --- | --- | --- |
| OSV_API_BASE_URL | OSV API base URL | https://api.osv.dev |
| OSV_ECOSYSTEMS | Target ecosystems to collect (comma-separated) | (empty: no collection) |
| OSV_DB_PATH | SQLite DB path | ./osv.db |
| OSV_DATA_RETENTION_DAYS | Number of days to retain vulnerability data | 7 |

### Supported Ecosystems

Supports the following 36 ecosystems:

*AlmaLinux, Alpaquita, Alpine, Android, BellSoft Hardened Containers,
Bitnami, Chainguard, CRAN, crates.io, Debian, Echo, GHC, GIT,
GitHub Actions, Go, Hackage, Hex, Linux, Mageia, Maven, MinimOS,
npm, NuGet, openEuler, openSUSE, OSS-Fuzz, Packagist, Pub, PyPI,
Red Hat, Rocky Linux, RubyGems, SUSE, SwiftURL, Ubuntu, Wolfi*

Data for each ecosystem is fetched independently, and cursors are managed separately.

## Testing

```bash
# Run all tests
task test

# With coverage
task test-cover
```

## Report Generation

### Generate Reports

```bash
# Generate Markdown report (default)
task report-markdown

# Generate CSV report
task report-csv

# Generate JSONL report
task report-jsonl
```

### Custom Report Options

```bash
# Filter by ecosystem
./osv-scraper -report -format=markdown -output=./npm-report.md -ecosystem=npm

# Generate CSV for specific ecosystem
./osv-scraper -report -format=csv -output=./pypi-report.csv -ecosystem=PyPI

# All ecosystems in JSONL format
./osv-scraper -report -format=jsonl -output=./all-vulns.jsonl
```

## Development

### Code Quality Check

```bash
# Check code formatting
task fmt

# Fix code formatting
task fmt-fix

# Run static analysis
task vet

# Run all checks (test, format, vet)
task check
```

### Clean

```bash
# Remove built binary
task clean
```

## Database Schema

### source_cursor
Manages processing cursor (last processed time) for each ecosystem

```sql
CREATE TABLE source_cursor (
    source TEXT PRIMARY KEY,  -- Ecosystem name (e.g., "npm", "PyPI", "Go")
    cursor TEXT NOT NULL      -- Last processed time (RFC3339 format)
);
```

### vulnerability
Stores vulnerability information

```sql
CREATE TABLE vulnerability (
    id TEXT PRIMARY KEY,      -- Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx")
    modified TEXT NOT NULL    -- Last updated time (RFC3339 format)
);
```

### tombstone
Records deleted vulnerabilities (tombstones)

```sql
CREATE TABLE tombstone (
    id TEXT PRIMARY KEY,                                    -- Deleted vulnerability ID
    deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP      -- Deletion recorded time
);
```

## License

MIT
