## Development

### Architecture

<details>

```
osv-scraper/
├── cmd/osv-scraper/     # CLI entry point (~70 lines)
├── internal/            # Internal packages (Go standard)
│   ├── app/             # Application logic (fetch, report, help)
│   ├── config/          # Configuration management
│   ├── ecosystem/       # Ecosystem definitions & URL mapper
│   ├── fetcher/         # Sitemap fetcher & CSV fetcher
│   ├── osv/             # OSV scraper, API client & parser
│   ├── report/          # Report output (CSV, JSONL, Markdown)
│   ├── severity/        # CVSS severity parsing
│   └── store/           # SQLite storage (~470 lines)
├── docs/                # Documentation
└── go.mod
```

**Design Principles:**
- Simple, direct code over unnecessary abstractions (YAGNI)
- Go standard patterns (`internal/` for package privacy)
- Single responsibility: each package has a clear purpose
- Testability through straightforward code, not complex interfaces

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
