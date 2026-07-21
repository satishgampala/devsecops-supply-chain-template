package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/integrity"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/releasepolicy"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

func run(arguments []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("releaseverify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "path to release policy JSON")
	evidenceRoot := flags.String("evidence-root", "", "relative root containing release evidence")
	manifestPath := flags.String("manifest", "release-evidence.json", "manifest path beneath evidence root")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 release evaluation time")
	outputPath := flags.String("output", "", "path for release decision JSON")
	cosignBinary := flags.String("cosign", "cosign", "Cosign executable name or path")
	if err := flags.Parse(arguments); err != nil {
		return 2, fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 || anyBlank(*policyPath, *evidenceRoot, *manifestPath, *evaluationTime, *outputPath, *cosignBinary) {
		return 2, fmt.Errorf("-policy, -evidence-root, -manifest, -evaluation-time, -output, and -cosign are required")
	}

	policyFile, err := safeio.Open(*policyPath)
	if err != nil {
		return 2, fmt.Errorf("open release policy: %w", err)
	}
	policy, decodeErr := releasepolicy.DecodeStrict[releasepolicy.Policy](policyFile)
	closeErr := policyFile.Close()
	if decodeErr != nil {
		return 2, decodeErr
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close release policy: %w", closeErr)
	}
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return 2, fmt.Errorf("validate release policy: %w", err)
	}
	policyHash, err := integrity.HashFile(*policyPath)
	if err != nil {
		return 2, fmt.Errorf("hash release policy: %w", err)
	}

	store, err := releasepolicy.NewStore(*evidenceRoot)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	var manifest releasepolicy.Manifest
	manifestHash, err := store.ReadRootJSON(*manifestPath, &manifest)
	if err != nil {
		return 2, fmt.Errorf("read release manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return 2, fmt.Errorf("validate release manifest: %w", err)
	}

	verifier := releasepolicy.CosignVerifier{Binary: strings.TrimSpace(*cosignBinary)}
	decision := releasepolicy.Evaluate(context.Background(), policy, policyHash, manifest, manifestHash, strings.TrimSpace(*evaluationTime), store, verifier)
	output, err := safeio.Create(*outputPath)
	if err != nil {
		return 2, fmt.Errorf("create release decision: %w", err)
	}
	encodeErr := releasepolicy.Encode(output, decision)
	closeErr = output.Close()
	if encodeErr != nil {
		return 2, fmt.Errorf("write release decision: %w", encodeErr)
	}
	if closeErr != nil {
		return 2, fmt.Errorf("close release decision: %w", closeErr)
	}
	if _, err := fmt.Fprintln(stdout, releasepolicy.Explain(decision)); err != nil {
		return 2, fmt.Errorf("write release summary: %w", err)
	}
	if !decision.Eligible {
		return 1, nil
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
