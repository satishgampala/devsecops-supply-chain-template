package signingpolicy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const maxSigningJSONSize = 1 << 20

const (
	ReasonArtifactDigestInvalid           = "ARTIFACT_DIGEST_INVALID"
	ReasonArtifactSetMismatch             = "ARTIFACT_SET_MISMATCH"
	ReasonArtifactVerificationFailed      = "ARTIFACT_VERIFICATION_FAILED"
	ReasonBundleDigestInvalid             = "BUNDLE_DIGEST_INVALID"
	ReasonCertificateIdentityMismatch     = "CERTIFICATE_IDENTITY_MISMATCH"
	ReasonCryptographicVerificationFailed = "CRYPTOGRAPHIC_VERIFICATION_FAILED"
	ReasonEmbeddedSCTMissing              = "EMBEDDED_SCT_MISSING"
	ReasonIssuerMismatch                  = "ISSUER_MISMATCH"
	ReasonObservationSchemaInvalid        = "OBSERVATION_SCHEMA_INVALID"
	ReasonRepositoryMismatch              = "REPOSITORY_MISMATCH"
	ReasonTransparencyLogMissing          = "TRANSPARENCY_LOG_MISSING"
	ReasonWorkflowNameMismatch            = "WORKFLOW_NAME_MISMATCH"
	ReasonWorkflowRefMismatch             = "WORKFLOW_REF_MISMATCH"
	ReasonWorkflowSHAInvalid              = "WORKFLOW_SHA_INVALID"
	ReasonWorkflowSHAMismatch             = "WORKFLOW_SHA_MISMATCH"
	ReasonWorkflowTriggerDenied           = "WORKFLOW_TRIGGER_DENIED"
)

func DecodeStrict[T any](reader io.Reader) (T, error) {
	var value T
	content, err := io.ReadAll(io.LimitReader(reader, maxSigningJSONSize+1))
	if err != nil {
		return value, fmt.Errorf("read JSON: %w", err)
	}
	if len(content) > maxSigningJSONSize {
		return value, fmt.Errorf("decode JSON: size limit exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return value, fmt.Errorf("decode JSON: trailing data")
	}
	return value, nil
}

func Encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func (policy *Policy) Normalize() {
	sort.Strings(policy.AllowedTriggers)
	sort.Slice(policy.RequiredArtifacts, func(i, j int) bool {
		return policy.RequiredArtifacts[i].Role < policy.RequiredArtifacts[j].Role
	})
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported signing policy schema")
	}
	if err := validateExactHTTPS("issuer", policy.Issuer); err != nil {
		return err
	}
	if err := validateExactHTTPS("certificate identity", policy.CertificateIdentity); err != nil {
		return err
	}
	if !validRepository(policy.Repository) {
		return fmt.Errorf("repository must be an exact owner/name value")
	}
	if !validLiteral(policy.WorkflowName) {
		return fmt.Errorf("workflow name must be an exact nonempty value")
	}
	if !validRef(policy.WorkflowRef) {
		return fmt.Errorf("workflow ref must be an exact branch ref")
	}
	if len(policy.AllowedTriggers) == 0 {
		return fmt.Errorf("at least one allowed trigger is required")
	}
	seenTriggers := make(map[string]struct{}, len(policy.AllowedTriggers))
	for _, trigger := range policy.AllowedTriggers {
		if trigger != "push" && trigger != "workflow_dispatch" {
			return fmt.Errorf("unsupported signing trigger %q", trigger)
		}
		if _, duplicate := seenTriggers[trigger]; duplicate {
			return fmt.Errorf("duplicate signing trigger %q", trigger)
		}
		seenTriggers[trigger] = struct{}{}
	}
	if len(policy.RequiredArtifacts) == 0 {
		return fmt.Errorf("at least one signed artifact is required")
	}
	seenRoles := make(map[string]struct{}, len(policy.RequiredArtifacts))
	seenPaths := make(map[string]struct{}, len(policy.RequiredArtifacts)*2)
	for _, artifact := range policy.RequiredArtifacts {
		if !validRole(artifact.Role) || !validBaseName(artifact.Path) || !validBaseName(artifact.Bundle) {
			return fmt.Errorf("invalid signing artifact rule")
		}
		if _, duplicate := seenRoles[artifact.Role]; duplicate {
			return fmt.Errorf("duplicate signing artifact role %q", artifact.Role)
		}
		seenRoles[artifact.Role] = struct{}{}
		for _, name := range []string{artifact.Path, artifact.Bundle} {
			if _, duplicate := seenPaths[name]; duplicate {
				return fmt.Errorf("duplicate signing artifact path %q", name)
			}
			seenPaths[name] = struct{}{}
		}
	}
	return nil
}

func Evaluate(policy Policy, observation Observation, expectedSHA string) Decision {
	reasons := make(map[string]struct{})
	add := func(reason string) { reasons[reason] = struct{}{} }
	if observation.SchemaVersion != SchemaVersion {
		add(ReasonObservationSchemaInvalid)
	}
	if !observation.CryptographicVerification {
		add(ReasonCryptographicVerificationFailed)
	}
	if !observation.TransparencyLogVerified {
		add(ReasonTransparencyLogMissing)
	}
	if !observation.EmbeddedSCTVerified {
		add(ReasonEmbeddedSCTMissing)
	}
	if observation.Issuer != policy.Issuer {
		add(ReasonIssuerMismatch)
	}
	if observation.CertificateIdentity != policy.CertificateIdentity {
		add(ReasonCertificateIdentityMismatch)
	}
	if observation.Repository != policy.Repository {
		add(ReasonRepositoryMismatch)
	}
	if observation.WorkflowName != policy.WorkflowName {
		add(ReasonWorkflowNameMismatch)
	}
	if observation.WorkflowRef != policy.WorkflowRef {
		add(ReasonWorkflowRefMismatch)
	}
	if !validHex(observation.WorkflowSHA, 40) || !validHex(expectedSHA, 40) {
		add(ReasonWorkflowSHAInvalid)
	} else if observation.WorkflowSHA != expectedSHA {
		add(ReasonWorkflowSHAMismatch)
	}
	if !contains(policy.AllowedTriggers, observation.WorkflowTrigger) {
		add(ReasonWorkflowTriggerDenied)
	}
	evaluateArtifacts(policy.RequiredArtifacts, observation.Artifacts, add)

	reasonCodes := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonCodes = append(reasonCodes, reason)
	}
	sort.Strings(reasonCodes)
	artifacts := append([]ArtifactObservation(nil), observation.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Role < artifacts[j].Role })
	return Decision{
		SchemaVersion: SchemaVersion,
		Eligible:      len(reasonCodes) == 0,
		ReasonCodes:   reasonCodes,
		Identity: IdentitySummary{
			Issuer:              observation.Issuer,
			CertificateIdentity: observation.CertificateIdentity,
			Repository:          observation.Repository,
			WorkflowName:        observation.WorkflowName,
			WorkflowRef:         observation.WorkflowRef,
			WorkflowSHA:         observation.WorkflowSHA,
			WorkflowTrigger:     observation.WorkflowTrigger,
		},
		Artifacts: artifacts,
	}
}

func evaluateArtifacts(rules []ArtifactRule, artifacts []ArtifactObservation, add func(string)) {
	expected := make(map[string]ArtifactRule, len(rules))
	for _, rule := range rules {
		expected[rule.Role] = rule
	}
	observed := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		rule, exists := expected[artifact.Role]
		if !exists {
			add(ReasonArtifactSetMismatch)
			continue
		}
		if _, duplicate := observed[artifact.Role]; duplicate {
			add(ReasonArtifactSetMismatch)
		}
		observed[artifact.Role] = struct{}{}
		if artifact.Path != rule.Path || artifact.Bundle != rule.Bundle {
			add(ReasonArtifactSetMismatch)
		}
		if !validHex(artifact.SHA256, 64) {
			add(ReasonArtifactDigestInvalid)
		}
		if !validHex(artifact.BundleSHA256, 64) {
			add(ReasonBundleDigestInvalid)
		}
		if !artifact.Verified {
			add(ReasonArtifactVerificationFailed)
		}
	}
	if len(observed) != len(expected) {
		add(ReasonArtifactSetMismatch)
	}
}

func validateExactHTTPS(label, value string) error {
	if !validLiteral(value) {
		return fmt.Errorf("%s must be an exact value", label)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTPS URI", label)
	}
	return nil
}

func validLiteral(value string) bool {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 512 {
		return false
	}
	if strings.ContainsAny(value, "*?[]{}()|+^$\\") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, character := range part {
			if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' && character != '.' {
				return false
			}
		}
	}
	return true
}

func validRef(value string) bool {
	return strings.HasPrefix(value, "refs/heads/") && validLiteral(value) && len(strings.TrimPrefix(value, "refs/heads/")) > 0
}

func validRole(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
			return false
		}
	}
	return true
}

func validBaseName(value string) bool {
	return validLiteral(value) && value != "." && value != ".." && filepath.Base(value) == value
}

func validHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == length
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
