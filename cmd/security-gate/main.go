package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
)

type pathsFlag []string

func (paths *pathsFlag) String() string {
	return strings.Join(*paths, ",")
}

func (paths *pathsFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("report path must not be empty")
	}
	*paths = append(*paths, value)
	return nil
}

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

func run() (int, error) {
	policyPath := flag.String("policy", "", "path to security policy JSON")
	outputPath := flag.String("output", "", "path for the gate decision")
	evaluationTime := flag.String("evaluation-time", "", "explicit RFC3339 evaluation time")
	var reportPaths pathsFlag
	flag.Var(&reportPaths, "report", "normalized report path; repeat for each scanner")
	flag.Parse()

	if *policyPath == "" || *outputPath == "" || *evaluationTime == "" || len(reportPaths) == 0 {
		return 2, fmt.Errorf("-policy, -output, -evaluation-time, and at least one -report are required")
	}
	now, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return 2, fmt.Errorf("parse evaluation time: %w", err)
	}
	policyFile, err := safeio.Open(*policyPath)
	if err != nil {
		return 2, fmt.Errorf("open policy: %w", err)
	}
	policy, decodeErr := securityreport.DecodeStrict[securityreport.Policy](policyFile)
	closeErr := policyFile.Close()
	if decodeErr != nil {
		return 2, fmt.Errorf("decode policy: %w", decodeErr)
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close policy: %w", closeErr)
	}
	policy.Normalize()

	sort.Strings(reportPaths)
	reports := make([]securityreport.Report, 0, len(reportPaths))
	for _, path := range reportPaths {
		file, err := safeio.Open(path)
		if err != nil {
			return 2, fmt.Errorf("open report %q: %w", path, err)
		}
		report, decodeErr := securityreport.DecodeStrict[securityreport.Report](file)
		closeErr := file.Close()
		if decodeErr != nil {
			return 2, fmt.Errorf("decode report %q: %w", path, decodeErr)
		}
		if closeErr != nil {
			return 2, fmt.Errorf("close report %q: %w", path, closeErr)
		}
		report.Normalize()
		reports = append(reports, report)
	}

	decision := securityreport.Evaluate(policy, reports, now)
	output, err := safeio.Create(*outputPath)
	if err != nil {
		return 2, fmt.Errorf("create gate decision: %w", err)
	}
	if err := securityreport.Encode(output, decision); err != nil {
		output.Close()
		return 2, fmt.Errorf("write gate decision: %w", err)
	}
	if err := output.Close(); err != nil {
		return 2, fmt.Errorf("close gate decision: %w", err)
	}
	if !decision.Eligible {
		return 1, fmt.Errorf("security gate rejected reports: %s", strings.Join(decision.ReasonCodes, ", "))
	}
	return 0, nil
}
