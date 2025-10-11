package app

import "fmt"

// ShowHelp displays usage information.
func ShowHelp() {
	fmt.Print(`
WARNING: This package is a PILOT VERSION and has NOT been reviewed by contributors.
Use with caution in production environments.

OSV Scraper - Vulnerability Database Tool

USAGE:
  osv-scraper [command] [options]

COMMANDS:
  -fetch              Fetch latest vulnerability data from OSV API
  -report             Generate report from local database
  -help               Show this help message

FETCH OPTIONS:
  Environment variables:
    OSV_ECOSYSTEMS          Comma-separated list of ecosystems (npm,pypi,go,etc)
    OSV_API_BASE_URL        OSV API base URL (default: https://api.osv.dev)
    OSV_DB_PATH             Database path (default: ./osv.db)
    OSV_DATA_RETENTION_DAYS Data retention period in days (default: 7)

REPORT OPTIONS:
  -format <format>    Output format: markdown, csv, jsonl (default: markdown)
  -output <file>      Output base file path (timestamp suffix appended; default: ./report.md)
  -ecosystem <name>   Filter by ecosystem (optional)
  -diff               Generate differential report (new/changed vulnerabilities only)

EXAMPLES:
  # Fetch vulnerability data
  OSV_ECOSYSTEMS=npm,pypi osv-scraper -fetch

  # Generate markdown report (creates report_<timestamp>.md)
  osv-scraper -report -format=markdown -output=report.md

  # Generate differential CSV report for npm only
  osv-scraper -report -diff -format=csv -ecosystem=npm -output=npm-diff.csv

For more information, see: https://github.com/pHo9UBenaA/osv-scraper/
`)
}
