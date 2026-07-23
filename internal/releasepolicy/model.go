package releasepolicy

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

const (
	ReasonArtifactDigestMismatch   = "ARTIFACT_DIGEST_MISMATCH"
	ReasonEvidenceHashMismatch     = "EVIDENCE_HASH_MISMATCH"
	ReasonEvaluationTimeMismatch   = "EVALUATION_TIME_MISMATCH"
	ReasonExceptionExpired         = "EXCEPTION_EXPIRED"
	ReasonIntegrityInvalid         = "INTEGRITY_INVALID"
	ReasonMalformedEvidence        = "MALFORMED_EVIDENCE"
	ReasonMissingEvidence          = "MISSING_EVIDENCE"
	ReasonPolicyDigestMismatch     = "POLICY_DIGEST_MISMATCH"
	ReasonProvenanceInvalid        = "PROVENANCE_INVALID"
	ReasonRequiredTestFailed       = "REQUIRED_TEST_FAILED"
	ReasonSBOMMissing              = "SBOM_MISSING"
	ReasonScannerFailed            = "SCANNER_FAILED"
	ReasonSignatureInvalid         = "SIGNATURE_INVALID"
	ReasonSignatureMissing         = "SIGNATURE_MISSING"
	ReasonToolUnavailable          = "TOOL_UNAVAILABLE"
	ReasonVulnerabilityBlocking    = "VULNERABILITY_BLOCKING"
	ReasonWorkflowIdentityMismatch = "WORKFLOW_IDENTITY_MISMATCH"
)

type Policy struct {
	SchemaVersion         string   `json:"schemaVersion"`
	Version               string   `json:"version"`
	ArtifactName          string   `json:"artifactName"`
	SourceURI             string   `json:"sourceURI"`
	Platform              string   `json:"platform"`
	Module                string   `json:"module"`
	GoVersion             string   `json:"goVersion"`
	ProvenanceBuildType   string   `json:"provenanceBuildType"`
	ProvenanceBuilderID   string   `json:"provenanceBuilderID"`
	SourceDateEpoch       int64    `json:"sourceDateEpoch"`
	SecurityPolicySHA256  string   `json:"securityPolicySHA256"`
	SigningPolicySHA256   string   `json:"signingPolicySHA256"`
	CosignVersion         string   `json:"cosignVersion"`
	MaxAcceptedExceptions int      `json:"maxAcceptedExceptions"`
	RequiredTests         []string `json:"requiredTests"`
	RequiredScanners      []string `json:"requiredScanners"`
}

type Manifest struct {
	SchemaVersion       string            `json:"schemaVersion"`
	ReleasePolicySHA256 string            `json:"releasePolicySHA256"`
	EvaluationTime      string            `json:"evaluationTime"`
	Artifact            Artifact          `json:"artifact"`
	Tests               EvidenceRef       `json:"tests"`
	Security            SecurityEvidence  `json:"security"`
	Integrity           IntegrityEvidence `json:"integrity"`
	Signing             SigningEvidence   `json:"signing"`
}

type Artifact struct {
	Name           string      `json:"name"`
	ManifestDigest string      `json:"manifestDigest"`
	Archive        EvidenceRef `json:"archive"`
	SourceURI      string      `json:"sourceURI"`
	SourceDigest   string      `json:"sourceDigest"`
	Platform       string      `json:"platform"`
}

type EvidenceRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type SecurityEvidence struct {
	Policy   EvidenceRef  `json:"policy"`
	Reports  []ScannerRef `json:"reports"`
	Decision EvidenceRef  `json:"decision"`
}

type ScannerRef struct {
	ID string `json:"id"`
	EvidenceRef
}

type IntegrityEvidence struct {
	SBOM         EvidenceRef `json:"sbom"`
	Provenance   EvidenceRef `json:"provenance"`
	Verification EvidenceRef `json:"verification"`
}

type SigningEvidence struct {
	Policy   EvidenceRef `json:"policy"`
	Decision EvidenceRef `json:"decision"`
}

type TestSummary struct {
	SchemaVersion string       `json:"schemaVersion"`
	SourceDigest  string       `json:"sourceDigest"`
	Tests         []TestResult `json:"tests"`
}

type TestResult struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Ref   string `json:"ref"`
}

type Decision struct {
	SchemaVersion  string            `json:"schemaVersion"`
	PolicyVersion  string            `json:"policyVersion"`
	PolicySHA256   string            `json:"policySHA256"`
	ManifestSHA256 string            `json:"manifestSHA256"`
	EvaluatedAt    string            `json:"evaluatedAt"`
	Eligible       bool              `json:"eligible"`
	ReasonCodes    []string          `json:"reasonCodes"`
	Artifact       DecisionArtifact  `json:"artifact"`
	Evidence       []EvidenceSummary `json:"evidence"`
}

type DecisionArtifact struct {
	Name           string `json:"name"`
	ManifestDigest string `json:"manifestDigest"`
	ArchiveSHA256  string `json:"archiveSHA256"`
	SourceDigest   string `json:"sourceDigest"`
	Platform       string `json:"platform"`
}

type EvidenceSummary struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	State  string `json:"state"`
}

func (policy *Policy) Normalize() {
	sort.Strings(policy.RequiredTests)
	sort.Strings(policy.RequiredScanners)
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != SchemaVersion || strings.TrimSpace(policy.Version) == "" {
		return fmt.Errorf("unsupported release policy identity")
	}
	if strings.TrimSpace(policy.ArtifactName) == "" || strings.ContainsAny(policy.ArtifactName, "@:") {
		return fmt.Errorf("artifact name must not contain a mutable or embedded digest reference")
	}
	for label, value := range map[string]string{
		"source URI":            policy.SourceURI,
		"provenance build type": policy.ProvenanceBuildType,
		"provenance builder ID": policy.ProvenanceBuilderID,
	} {
		if !validHTTPS(value) {
			return fmt.Errorf("%s must be an absolute HTTPS URI", label)
		}
	}
	if policy.Platform != "linux/amd64" || strings.TrimSpace(policy.Module) == "" || !strings.HasPrefix(policy.GoVersion, "go1.") {
		return fmt.Errorf("unsupported release platform or runtime contract")
	}
	if policy.SourceDateEpoch < 0 || policy.MaxAcceptedExceptions < 0 {
		return fmt.Errorf("release numeric limits must not be negative")
	}
	if !validHex(policy.SecurityPolicySHA256, 64) || !validHex(policy.SigningPolicySHA256, 64) {
		return fmt.Errorf("required policy digest is invalid")
	}
	if policy.CosignVersion == "" || strings.ContainsAny(policy.CosignVersion, "*?[]{}()|+^$\\") {
		return fmt.Errorf("Cosign version must be exact")
	}
	if err := validateUniqueIDs("required test", policy.RequiredTests); err != nil {
		return err
	}
	if err := validateUniqueIDs("required scanner", policy.RequiredScanners); err != nil {
		return err
	}
	return nil
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported release manifest schema")
	}
	if !validHex(manifest.ReleasePolicySHA256, 64) {
		return fmt.Errorf("release policy digest is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.EvaluationTime); err != nil {
		return fmt.Errorf("evaluation time must be RFC3339")
	}
	if strings.TrimSpace(manifest.Artifact.Name) == "" || strings.ContainsAny(manifest.Artifact.Name, "@:") || !validDigest(manifest.Artifact.ManifestDigest) {
		return fmt.Errorf("artifact identity is invalid")
	}
	if !validHTTPS(manifest.Artifact.SourceURI) || !validHex(manifest.Artifact.SourceDigest, 40) || manifest.Artifact.Platform == "" {
		return fmt.Errorf("artifact source or platform is invalid")
	}
	refs := []EvidenceRef{
		manifest.Artifact.Archive,
		manifest.Tests,
		manifest.Security.Policy,
		manifest.Security.Decision,
		manifest.Integrity.SBOM,
		manifest.Integrity.Provenance,
		manifest.Integrity.Verification,
		manifest.Signing.Policy,
		manifest.Signing.Decision,
	}
	seenScannerIDs := make(map[string]struct{}, len(manifest.Security.Reports))
	for _, report := range manifest.Security.Reports {
		if !validID(report.ID) {
			return fmt.Errorf("scanner evidence ID is invalid")
		}
		if _, duplicate := seenScannerIDs[report.ID]; duplicate {
			return fmt.Errorf("duplicate scanner evidence ID %q", report.ID)
		}
		seenScannerIDs[report.ID] = struct{}{}
		refs = append(refs, report.EvidenceRef)
	}
	seenPaths := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return err
		}
		if _, duplicate := seenPaths[ref.Path]; duplicate {
			return fmt.Errorf("duplicate evidence path %q", ref.Path)
		}
		seenPaths[ref.Path] = struct{}{}
	}
	return nil
}

func (ref EvidenceRef) Validate() error {
	if !validRelativePath(ref.Path) || !validHex(ref.SHA256, 64) {
		return fmt.Errorf("invalid evidence reference")
	}
	return nil
}

func validateUniqueIDs(label string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("at least one %s is required", label)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validID(value) {
			return fmt.Errorf("%s ID %q is invalid", label, value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s ID %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
			return false
		}
	}
	return true
}

func validHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") || filepath.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validHex(strings.TrimPrefix(value, "sha256:"), 64)
}

func validHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == length
}
