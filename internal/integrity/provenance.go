package integrity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

const (
	InTotoStatementV1 = "https://in-toto.io/Statement/v1"
	SLSAProvenanceV1  = "https://slsa.dev/provenance/v1"
)

type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Subject  `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     Provenance `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Provenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   ExternalParameters   `json:"externalParameters"`
	InternalParameters   map[string]any       `json:"internalParameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies"`
}

type ExternalParameters struct {
	Source          SourceDescriptor `json:"source"`
	Platform        string           `json:"platform"`
	SourceDateEpoch int64            `json:"sourceDateEpoch"`
}

type SourceDescriptor struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

type ResourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type RunDetails struct {
	Builder  Builder     `json:"builder"`
	Metadata RunMetadata `json:"metadata"`
}

type Builder struct {
	ID string `json:"id"`
}

type RunMetadata struct {
	InvocationID string `json:"invocationId"`
}

type ProvenanceInput struct {
	SubjectName     string
	SourceURI       string
	SourceDigest    string
	BuildType       string
	BuilderID       string
	InvocationID    string
	SourceDateEpoch int64
}

func GenerateProvenance(info ArchiveInfo, input ProvenanceInput) (Statement, error) {
	if err := validateProvenanceInput(info, input); err != nil {
		return Statement{}, err
	}
	statement := Statement{
		Type: InTotoStatementV1,
		Subject: []Subject{
			{Name: input.SubjectName, Digest: map[string]string{"sha256": strings.TrimPrefix(info.ManifestDigest, "sha256:")}},
		},
		PredicateType: SLSAProvenanceV1,
		Predicate: Provenance{
			BuildDefinition: BuildDefinition{
				BuildType: input.BuildType,
				ExternalParameters: ExternalParameters{
					Source:          SourceDescriptor{URI: input.SourceURI, Digest: input.SourceDigest},
					Platform:        info.OS + "/" + info.Architecture,
					SourceDateEpoch: input.SourceDateEpoch,
				},
				InternalParameters: map[string]any{},
				ResolvedDependencies: []ResourceDescriptor{
					{URI: input.SourceURI, Digest: map[string]string{"gitCommit": input.SourceDigest}},
				},
			},
			RunDetails: RunDetails{
				Builder:  Builder{ID: input.BuilderID},
				Metadata: RunMetadata{InvocationID: input.InvocationID},
			},
		},
	}
	sort.Slice(statement.Subject, func(i, j int) bool { return statement.Subject[i].Name < statement.Subject[j].Name })
	sort.Slice(statement.Predicate.BuildDefinition.ResolvedDependencies, func(i, j int) bool {
		return statement.Predicate.BuildDefinition.ResolvedDependencies[i].URI < statement.Predicate.BuildDefinition.ResolvedDependencies[j].URI
	})
	return statement, nil
}

func DecodeStatement(reader io.Reader) (Statement, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var statement Statement
	if err := decoder.Decode(&statement); err != nil {
		return Statement{}, fmt.Errorf("decode provenance: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Statement{}, fmt.Errorf("decode provenance: trailing data")
	}
	return statement, nil
}

func VerifyProvenance(statement Statement, info ArchiveInfo, expected ProvenanceInput) error {
	if err := validateProvenanceInput(info, expected); err != nil {
		return err
	}
	if statement.Type != InTotoStatementV1 || statement.PredicateType != SLSAProvenanceV1 {
		return fmt.Errorf("unsupported provenance statement identity")
	}
	if len(statement.Subject) != 1 {
		return fmt.Errorf("provenance must contain exactly one subject")
	}
	subject := statement.Subject[0]
	if subject.Name != expected.SubjectName || len(subject.Digest) != 1 || subject.Digest["sha256"] != strings.TrimPrefix(info.ManifestDigest, "sha256:") {
		return fmt.Errorf("provenance subject does not match OCI manifest")
	}
	definition := statement.Predicate.BuildDefinition
	if definition.BuildType != expected.BuildType {
		return fmt.Errorf("provenance build type mismatch")
	}
	parameters := definition.ExternalParameters
	if parameters.Source.URI != expected.SourceURI || parameters.Source.Digest != expected.SourceDigest {
		return fmt.Errorf("provenance source mismatch")
	}
	if parameters.Platform != info.OS+"/"+info.Architecture || parameters.SourceDateEpoch != expected.SourceDateEpoch {
		return fmt.Errorf("provenance build parameters mismatch")
	}
	if len(definition.InternalParameters) != 0 {
		return fmt.Errorf("provenance contains unexpected internal parameters")
	}
	if len(definition.ResolvedDependencies) != 1 {
		return fmt.Errorf("provenance must contain one resolved source dependency")
	}
	dependency := definition.ResolvedDependencies[0]
	if dependency.URI != expected.SourceURI || len(dependency.Digest) != 1 || dependency.Digest["gitCommit"] != expected.SourceDigest {
		return fmt.Errorf("provenance resolved source mismatch")
	}
	if statement.Predicate.RunDetails.Builder.ID != expected.BuilderID {
		return fmt.Errorf("provenance builder mismatch")
	}
	if statement.Predicate.RunDetails.Metadata.InvocationID != expected.InvocationID {
		return fmt.Errorf("provenance invocation mismatch")
	}
	return nil
}

func validateProvenanceInput(info ArchiveInfo, input ProvenanceInput) error {
	if !validSHA256Digest(info.ManifestDigest) || info.OS != "linux" || info.Architecture != "amd64" {
		return fmt.Errorf("invalid OCI subject information")
	}
	if strings.TrimSpace(input.SubjectName) == "" || strings.Contains(input.SubjectName, "@") {
		return fmt.Errorf("subject name must be immutable-reference base without digest")
	}
	if err := validateHTTPSURI("source URI", input.SourceURI); err != nil {
		return err
	}
	if !validGitDigest(input.SourceDigest) {
		return fmt.Errorf("source digest is invalid")
	}
	if err := validateHTTPSURI("build type", input.BuildType); err != nil {
		return err
	}
	if err := validateHTTPSURI("builder id", input.BuilderID); err != nil {
		return err
	}
	if strings.TrimSpace(input.InvocationID) == "" {
		return fmt.Errorf("invocation id is required")
	}
	if input.SourceDateEpoch < 0 {
		return fmt.Errorf("source date epoch must not be negative")
	}
	return nil
}

func validateHTTPSURI(label, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URI", label)
	}
	return nil
}

func validGitDigest(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == len(value) && value == strings.ToLower(value)
}
