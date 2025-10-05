## Development

### Architecture

<details>

```
osv-scraper/
├── cmd/osv-scraper/     # CLI entry point
├── src/                 # Source code
│   ├── config/          # Configuration management (environment variable loading)
│   ├── ecosystem/       # Ecosystem definitions & URL mapper
│   ├── fetcher/         # Sitemap fetcher & CSV fetcher
│   ├── metrics/         # Metrics collection (GitHub, npm, PyPI)
│   ├── osv/             # OSV scraper, API client & parser
│   ├── report/          # Report output (CSV, JSONL, Markdown)
│   └── store/           # SQLite storage
├── docs/                # Documentation
└── go.mod
```

</details>

### Testing

```bash
# Run all tests
task test

# With coverage
task test-cover
```

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
