package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("sarif-normalizer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "path to scanner SARIF")
	output := flags.String("output", "", "path for normalized JSON")
	scannerName := flags.String("scanner", "", "stable scanner name")
	reference := flags.String("reference", "", "immutable scanner reference")
	stateText := flags.String("state", string(securityreport.ScannerCompleted), "completed, failed, or not_run")
	diagnostic := flags.String("diagnostic", "", "sanitized failure diagnostic")
	databaseUpdatedAt := flags.String("database-updated-at", "", "scanner database timestamp")
	sourceDigest := flags.String("source-digest", "", "source commit scanned for the candidate")
	subjectDigest := flags.String("subject-digest", "", "candidate OCI manifest digest")
	scannedAt := flags.String("scanned-at", "", "scan start time in RFC3339")
	exitCode := flags.Int("scanner-exit-code", -1, "observed scanner process exit code")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}

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
		if *exitCode != -1 {
			if err := securityreport.ValidateScannerExit(report, *exitCode); err != nil {
				return err
			}
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
	if strings.TrimSpace(*databaseUpdatedAt) != "" {
		report.DatabaseUpdatedAt = strings.TrimSpace(*databaseUpdatedAt)
	}
	report.SourceDigest = *sourceDigest
	report.SubjectDigest = *subjectDigest
	report.ScannedAt = *scannedAt
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
