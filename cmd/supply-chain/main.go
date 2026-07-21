package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/integrity"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
)

const usage = "usage: supply-chain <subject|canonicalize|provenance|verify> [flags]"

type verificationResult struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Verified         bool              `json:"verified"`
	Subject          integrity.Subject `json:"subject"`
	ArchiveSHA256    string            `json:"archiveSHA256"`
	SBOMSHA256       string            `json:"sbomSHA256"`
	ProvenanceSHA256 string            `json:"provenanceSHA256"`
	Platform         string            `json:"platform"`
}

func main() {
	if err := execute(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func execute(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New(usage)
	}
	switch arguments[0] {
	case "subject":
		return subjectCommand(arguments[1:], stdout)
	case "canonicalize":
		return canonicalizeCommand(arguments[1:])
	case "provenance":
		return provenanceCommand(arguments[1:])
	case "verify":
		return verifyCommand(arguments[1:])
	default:
		return errors.New(usage)
	}
}

func subjectCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("subject", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact", "", "path to OCI archive")
	format := flags.String("format", "digest", "digest or json")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse subject flags: %w", err)
	}
	if flags.NArg() != 0 || strings.TrimSpace(*artifact) == "" {
		return errors.New("subject: -artifact is required")
	}
	info, err := integrity.InspectOCIArchive(*artifact)
	if err != nil {
		return fmt.Errorf("inspect OCI archive: %w", err)
	}
	switch *format {
	case "digest":
		_, err = fmt.Fprintln(stdout, info.ManifestDigest)
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(info)
	default:
		return errors.New("subject: -format must be digest or json")
	}
	if err != nil {
		return fmt.Errorf("write subject: %w", err)
	}
	return nil
}

func canonicalizeCommand(arguments []string) error {
	flags := flag.NewFlagSet("canonicalize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "path to raw SPDX JSON")
	output := flags.String("output", "", "path for canonical SPDX projection")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse canonicalize flags: %w", err)
	}
	if flags.NArg() != 0 || strings.TrimSpace(*input) == "" || strings.TrimSpace(*output) == "" {
		return errors.New("canonicalize: -input and -output are required")
	}
	file, err := safeio.Open(*input)
	if err != nil {
		return fmt.Errorf("open raw SPDX: %w", err)
	}
	content, canonicalErr := integrity.CanonicalizeSPDX(file)
	closeErr := file.Close()
	if canonicalErr != nil {
		return canonicalErr
	}
	if closeErr != nil {
		return fmt.Errorf("close raw SPDX: %w", closeErr)
	}
	return writeBytes(*output, content)
}

func provenanceCommand(arguments []string) error {
	flags, values := newProvenanceFlags("provenance")
	artifact := flags.String("artifact", "", "path to OCI archive")
	output := flags.String("output", "", "path for provenance JSON")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse provenance flags: %w", err)
	}
	if flags.NArg() != 0 || strings.TrimSpace(*artifact) == "" || strings.TrimSpace(*output) == "" {
		return errors.New("provenance: -artifact and -output are required")
	}
	info, err := integrity.InspectOCIArchive(*artifact)
	if err != nil {
		return fmt.Errorf("inspect OCI archive: %w", err)
	}
	statement, err := integrity.GenerateProvenance(info, values.input())
	if err != nil {
		return fmt.Errorf("generate provenance: %w", err)
	}
	return writeJSON(*output, statement)
}

func verifyCommand(arguments []string) error {
	flags, values := newProvenanceFlags("verify")
	artifact := flags.String("artifact", "", "path to OCI archive")
	sbom := flags.String("sbom", "", "path to raw SPDX JSON")
	provenance := flags.String("provenance", "", "path to provenance JSON")
	module := flags.String("module", "", "expected application module")
	goVersion := flags.String("go-version", "", "expected Go standard-library version")
	output := flags.String("output", "", "path for verification result")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse verify flags: %w", err)
	}
	if flags.NArg() != 0 || anyBlank(*artifact, *sbom, *provenance, *module, *goVersion, *output) {
		return errors.New("verify: -artifact, -sbom, -provenance, -module, -go-version, and -output are required")
	}
	info, err := integrity.InspectOCIArchive(*artifact)
	if err != nil {
		return fmt.Errorf("inspect OCI archive: %w", err)
	}
	sbomFile, err := safeio.Open(*sbom)
	if err != nil {
		return fmt.Errorf("open SPDX: %w", err)
	}
	document, decodeErr := integrity.DecodeSPDX(sbomFile)
	closeErr := sbomFile.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if closeErr != nil {
		return fmt.Errorf("close SPDX: %w", closeErr)
	}
	if err := integrity.VerifySPDX(document, info.ManifestDigest, *module, *goVersion); err != nil {
		return fmt.Errorf("verify SPDX: %w", err)
	}
	provenanceFile, err := safeio.Open(*provenance)
	if err != nil {
		return fmt.Errorf("open provenance: %w", err)
	}
	statement, decodeErr := integrity.DecodeStatement(provenanceFile)
	closeErr = provenanceFile.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if closeErr != nil {
		return fmt.Errorf("close provenance: %w", closeErr)
	}
	input := values.input()
	if err := integrity.VerifyProvenance(statement, info, input); err != nil {
		return fmt.Errorf("verify provenance: %w", err)
	}
	sbomHash, err := integrity.HashFile(*sbom)
	if err != nil {
		return fmt.Errorf("hash SPDX: %w", err)
	}
	provenanceHash, err := integrity.HashFile(*provenance)
	if err != nil {
		return fmt.Errorf("hash provenance: %w", err)
	}
	result := verificationResult{
		SchemaVersion: "1.0",
		Verified:      true,
		Subject: integrity.Subject{
			Name:   input.SubjectName,
			Digest: map[string]string{"sha256": strings.TrimPrefix(info.ManifestDigest, "sha256:")},
		},
		ArchiveSHA256:    info.ArchiveSHA256,
		SBOMSHA256:       sbomHash,
		ProvenanceSHA256: provenanceHash,
		Platform:         info.OS + "/" + info.Architecture,
	}
	return writeJSON(*output, result)
}

type provenanceFlags struct {
	subjectName     *string
	sourceURI       *string
	sourceDigest    *string
	buildType       *string
	builderID       *string
	invocationID    *string
	sourceDateEpoch *int64
}

func newProvenanceFlags(name string) (*flag.FlagSet, provenanceFlags) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	values := provenanceFlags{
		subjectName:     flags.String("subject-name", "", "immutable-reference base name"),
		sourceURI:       flags.String("source-uri", "", "HTTPS source repository URI"),
		sourceDigest:    flags.String("source-digest", "", "full source commit digest"),
		buildType:       flags.String("build-type", "", "HTTPS build-type URI"),
		builderID:       flags.String("builder-id", "", "HTTPS builder identity URI"),
		invocationID:    flags.String("invocation-id", "", "stable build invocation identifier"),
		sourceDateEpoch: flags.Int64("source-date-epoch", 0, "reproducible build epoch"),
	}
	return flags, values
}

func (values provenanceFlags) input() integrity.ProvenanceInput {
	return integrity.ProvenanceInput{
		SubjectName:     strings.TrimSpace(*values.subjectName),
		SourceURI:       strings.TrimSpace(*values.sourceURI),
		SourceDigest:    strings.TrimSpace(*values.sourceDigest),
		BuildType:       strings.TrimSpace(*values.buildType),
		BuilderID:       strings.TrimSpace(*values.builderID),
		InvocationID:    strings.TrimSpace(*values.invocationID),
		SourceDateEpoch: *values.sourceDateEpoch,
	}
}

func anyBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func writeJSON(path string, value any) error {
	file, err := safeio.Create(path)
	if err != nil {
		return fmt.Errorf("create JSON output: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	closeErr := file.Close()
	if encodeErr != nil {
		return fmt.Errorf("encode JSON output: %w", encodeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close JSON output: %w", closeErr)
	}
	return nil
}

func writeBytes(path string, content []byte) error {
	file, err := safeio.Create(path)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	_, writeErr := file.Write(content)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write output: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close output: %w", closeErr)
	}
	return nil
}
