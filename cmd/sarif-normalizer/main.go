package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run() error {
	input := flag.String("input", "", "path to scanner SARIF")
	output := flag.String("output", "", "path for normalized JSON")
	scannerName := flag.String("scanner", "", "stable scanner name")
	reference := flag.String("reference", "", "immutable scanner reference")
	stateText := flag.String("state", string(securityreport.ScannerCompleted), "completed, failed, or not_run")
	diagnostic := flag.String("diagnostic", "", "sanitized failure diagnostic")
	databaseUpdatedAt := flag.String("database-updated-at", "", "scanner database timestamp")
	flag.Parse()

	if strings.TrimSpace(*output) == "" {
		return fmt.Errorf("-output is required")
	}
	scanner := securityreport.Scanner{Name: strings.TrimSpace(*scannerName), Reference: strings.TrimSpace(*reference)}
	state := securityreport.ScannerState(*stateText)
	var report securityreport.Report
	if state == securityreport.ScannerCompleted {
		if strings.TrimSpace(*input) == "" {
			return fmt.Errorf("-input is required for a completed scan")
		}
		file, err := safeio.Open(*input)
		if err != nil {
			return fmt.Errorf("open SARIF: %w", err)
		}
		report, err = securityreport.NormalizeSARIF(file, scanner)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return fmt.Errorf("close SARIF: %w", closeErr)
		}
	} else {
		report = securityreport.Report{
			SchemaVersion: securityreport.SchemaVersion,
			Scanner:       scanner,
			State:         state,
			Findings:      []securityreport.Finding{},
			Diagnostic:    strings.TrimSpace(*diagnostic),
		}
	}
	report.DatabaseUpdatedAt = strings.TrimSpace(*databaseUpdatedAt)
	report.Normalize()
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate normalized report: %w", err)
	}
	file, err := safeio.Create(*output)
	if err != nil {
		return fmt.Errorf("create normalized report: %w", err)
	}
	if err := securityreport.Encode(file, report); err != nil {
		file.Close()
		return fmt.Errorf("write normalized report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close normalized report: %w", err)
	}
	return nil
}
