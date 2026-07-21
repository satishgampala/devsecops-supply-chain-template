package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/signingpolicy"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

func run(arguments []string) (int, error) {
	flags := flag.NewFlagSet("signing-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "path to signing identity policy")
	observationPath := flags.String("observation", "", "path to observed verification claims")
	expectedSHA := flags.String("expected-sha", "", "exact workflow commit SHA")
	outputPath := flags.String("output", "", "path for the policy decision")
	if err := flags.Parse(arguments); err != nil {
		return 2, fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 || anyBlank(*policyPath, *observationPath, *expectedSHA, *outputPath) {
		return 2, fmt.Errorf("-policy, -observation, -expected-sha, and -output are required")
	}

	policyFile, err := safeio.Open(*policyPath)
	if err != nil {
		return 2, fmt.Errorf("open signing policy: %w", err)
	}
	policy, decodeErr := signingpolicy.DecodeStrict[signingpolicy.Policy](policyFile)
	closeErr := policyFile.Close()
	if decodeErr != nil {
		return 2, decodeErr
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close signing policy: %w", closeErr)
	}
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return 2, fmt.Errorf("validate signing policy: %w", err)
	}

	observationFile, err := safeio.Open(*observationPath)
	if err != nil {
		return 2, fmt.Errorf("open signing observation: %w", err)
	}
	observation, decodeErr := signingpolicy.DecodeStrict[signingpolicy.Observation](observationFile)
	closeErr = observationFile.Close()
	if decodeErr != nil {
		return 2, decodeErr
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close signing observation: %w", closeErr)
	}

	decision := signingpolicy.Evaluate(policy, observation, strings.TrimSpace(*expectedSHA))
	output, err := safeio.Create(*outputPath)
	if err != nil {
		return 2, fmt.Errorf("create signing decision: %w", err)
	}
	encodeErr := signingpolicy.Encode(output, decision)
	closeErr = output.Close()
	if encodeErr != nil {
		return 2, fmt.Errorf("write signing decision: %w", encodeErr)
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close signing decision: %w", closeErr)
	}
	if !decision.Eligible {
		return 1, fmt.Errorf("signing policy rejected observation: %s", strings.Join(decision.ReasonCodes, ", "))
	}
	return 0, nil
}

func anyBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
