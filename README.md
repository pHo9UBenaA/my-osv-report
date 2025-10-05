# OSV Scraper

> ⚠️ **WARNING: PILOT VERSION**
>
> This package is a **PILOT VERSION** and has **NOT been reviewed by contributors**.
> Use with caution in production environments. The data and functionality provided
> should be validated independently before making critical security decisions.

A tool to fetch vulnerability information from OSV (Open Source Vulnerabilities) using sitemaps, CSV archives, and OSV API.

## Quick Start

### 1. Setup Environment

```bash
# Copy the example configuration file
cp .env.example .env

# Edit .env to configure ecosystems to monitor
# Example: OSV_ECOSYSTEMS=npm,pypi,go
```

### 2. Fetch Vulnerability Data

```bash
# Fetch latest vulnerability information from OSV API
task fetch

# Or directly:
./osv-scraper -fetch
```

### 3. Generate Reports

```bash
# Generate a markdown report
task report-markdown

# Generate a CSV report
task report-csv

# Generate differential report (only new/changed vulnerabilities)
task report-diff-markdown
```

## Usage

### Available Commands

```bash
# Show help and command list
task --list
# Or
task run
```

### Configuration

Configure the application using environment variables or a `.env` file:

NOTE: Environment Variables

<details>

| Variable Name | Description | Default Value |
| --- | --- | --- |
| OSV_API_BASE_URL | OSV API base URL | https://api.osv.dev |
| OSV_ECOSYSTEMS | Target ecosystems to collect (comma-separated) | (empty: no collection) |
| OSV_DB_PATH | SQLite DB path | ./osv.db |
| OSV_DATA_RETENTION_DAYS | Number of days to retain vulnerability data | 7 |

</details>

### Supported Ecosystems

Supports the following 36 ecosystems:

*AlmaLinux, Alpaquita, Alpine, Android, BellSoft Hardened Containers,
Bitnami, Chainguard, CRAN, crates.io, Debian, Echo, GHC, GIT,
GitHub Actions, Go, Hackage, Hex, Linux, Mageia, Maven, MinimOS,
npm, NuGet, openEuler, openSUSE, OSS-Fuzz, Packagist, Pub, PyPI,
Red Hat, Rocky Linux, RubyGems, SUSE, SwiftURL, Ubuntu, Wolfi*

Data for each ecosystem is fetched independently, and cursors are managed separately.


## License

MIT
