package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/pHo9UBenaA/osv-scraper/internal/app"
	"github.com/pHo9UBenaA/osv-scraper/internal/config"
	"github.com/pHo9UBenaA/osv-scraper/internal/store"
)

var (
	fetchMode       = flag.Bool("fetch", false, "Fetch vulnerability data from OSV API")
	reportMode      = flag.Bool("report", false, "Generate report instead of scraping")
	reportFormat    = flag.String("format", "markdown", "Report format: markdown, csv, jsonl")
	reportOutput    = flag.String("output", "./report.md", "Report output base path (timestamp suffix appended before extension)")
	reportEcosystem = flag.String("ecosystem", "", "Filter report by ecosystem (empty = all)")
	reportDiff      = flag.Bool("diff", false, "Generate differential report (only new/changed vulnerabilities)")
	helpMode        = flag.Bool("help", false, "Show help message")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	if *helpMode || (!*fetchMode && !*reportMode) {
		app.ShowHelp()
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer st.Close()

	if *reportMode {
		return app.GenerateReport(ctx, st, app.ReportOptions{
			Format:    *reportFormat,
			Output:    *reportOutput,
			Ecosystem: *reportEcosystem,
			Diff:      *reportDiff,
		})
	}

	if *fetchMode {
		return app.Fetch(ctx, cfg, st)
	}

	return nil
}
