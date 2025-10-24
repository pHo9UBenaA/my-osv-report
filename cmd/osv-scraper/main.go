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

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		app.ShowHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]

	switch cmd {
	case "fetch":
		if err := runFetch(); err != nil {
			log.Fatalf("error: %v", err)
		}
	case "report":
		if err := runReport(); err != nil {
			log.Fatalf("error: %v", err)
		}
	case "help", "-h", "--help":
		app.ShowHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		app.ShowHelp()
		os.Exit(1)
	}
}

func runFetch() error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer st.Close()

	return app.Fetch(ctx, cfg, st)
}

func runReport() error {
	reportCmd := flag.NewFlagSet("report", flag.ExitOnError)
	format := reportCmd.String("format", "markdown", "Report format: markdown, csv, jsonl")
	outputDir := reportCmd.String("output-dir", ".", "Report output directory")
	filePrefix := reportCmd.String("file-prefix", "report", "Report filename prefix (timestamp and extension appended automatically)")
	ecosystem := reportCmd.String("ecosystem", "", "Filter report by ecosystem (empty = all)")
	diff := reportCmd.Bool("diff", false, "Generate differential report (only new/changed vulnerabilities)")

	if err := reportCmd.Parse(os.Args[2:]); err != nil {
		return err
	}

	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer st.Close()

	return app.GenerateReport(ctx, st, app.ReportOptions{
		Format:     *format,
		OutputDir:  *outputDir,
		FilePrefix: *filePrefix,
		Ecosystem:  *ecosystem,
		Diff:       *diff,
	})
}
