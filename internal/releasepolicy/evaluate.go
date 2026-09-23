package releasepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/integrity"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/signingpolicy"
)

type integrityVerification struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Verified         bool              `json:"verified"`
	Subject          integrity.Subject `json:"subject"`
	ArchiveSHA256    string            `json:"archiveSHA256"`
	SBOMSHA256       string            `json:"sbomSHA256"`
	ProvenanceSHA256 string            `json:"provenanceSHA256"`
	Platform         string            `json:"platform"`
}

type evaluator struct {
	ctx          context.Context
	policy       Policy
	policyHash   string
	manifestHash string
	expectedTime string
	manifest     Manifest
	store        *Store
	verifier     SignatureVerifier
	reasons      map[string]struct{}
	evidence     map[string]EvidenceSummary
	archive      integrity.ArchiveInfo
}

func Evaluate(ctx context.Context, policy Policy, policyHash string, manifest Manifest, manifestHash, expectedTime string, store *Store, verifier SignatureVerifier) Decision {
	evaluation := &evaluator{
		ctx:          ctx,
		policy:       policy,
		policyHash:   policyHash,
		manifestHash: manifestHash,
		expectedTime: expectedTime,
		manifest:     manifest,
		store:        store,
		verifier:     verifier,
		reasons:      make(map[string]struct{}),
		evidence:     make(map[string]EvidenceSummary),
	}
	if err := policy.Validate(); err != nil {
		evaluation.add(ReasonMalformedEvidence)
	}
	if err := manifest.Validate(); err != nil {
		evaluation.add(ReasonMalformedEvidence)
		return evaluation.decision()
	}
	if manifest.ReleasePolicySHA256 != policyHash {
		evaluation.add(ReasonPolicyDigestMismatch)
	}
	if manifest.EvaluationTime != expectedTime {
		evaluation.add(ReasonEvaluationTimeMismatch)
	}
	evaluation.verifyArtifactIdentity()
	evaluation.verifyTests()
	evaluation.verifySecurity()
	evaluation.verifyIntegrity()
	evaluation.verifySigning()
	return evaluation.decision()
}

func (evaluation *evaluator) verifyArtifactIdentity() {
	artifact := evaluation.manifest.Artifact
	if artifact.Name != evaluation.policy.ArtifactName || artifact.SourceURI != evaluation.policy.SourceURI || artifact.Platform != evaluation.policy.Platform {
		evaluation.add(ReasonArtifactDigestMismatch)
	}
	path, ok := evaluation.path("artifact", artifact.Archive, ReasonMissingEvidence)
	if !ok {
		evaluation.add(ReasonArtifactDigestMismatch)
		return
	}
	info, err := integrity.InspectOCIArchive(path)
	if err != nil {
		evaluation.invalidate("artifact", ReasonArtifactDigestMismatch)
		return
	}
	evaluation.archive = info
	if info.ManifestDigest != artifact.ManifestDigest || info.ArchiveSHA256 != artifact.Archive.SHA256 || info.OS+"/"+info.Architecture != artifact.Platform {
		evaluation.invalidate("artifact", ReasonArtifactDigestMismatch)
	}
}

func (evaluation *evaluator) verifyTests() {
	var summary TestSummary
	if !evaluation.json("tests", evaluation.manifest.Tests, ReasonMissingEvidence, &summary) {
		evaluation.add(ReasonRequiredTestFailed)
		return
	}
	if summary.SchemaVersion != SchemaVersion || summary.SourceDigest != evaluation.manifest.Artifact.SourceDigest {
		evaluation.invalidate("tests", ReasonRequiredTestFailed)
		return
	}
	states := make(map[string]string, len(summary.Tests))
	for _, result := range summary.Tests {
		if !validID(result.ID) || strings.TrimSpace(result.Ref) == "" {
			evaluation.invalidate("tests", ReasonRequiredTestFailed)
			continue
		}
		if _, duplicate := states[result.ID]; duplicate {
			evaluation.invalidate("tests", ReasonRequiredTestFailed)
		}
		states[result.ID] = result.State
	}
	for _, required := range evaluation.policy.RequiredTests {
		if states[required] != "passed" {
			evaluation.invalidate("tests", ReasonRequiredTestFailed)
		}
	}
	if len(states) != len(evaluation.policy.RequiredTests) {
		evaluation.invalidate("tests", ReasonRequiredTestFailed)
	}
}

func (evaluation *evaluator) verifySecurity() {
	securityEvidence := evaluation.manifest.Security
	if securityEvidence.Policy.SHA256 != evaluation.policy.SecurityPolicySHA256 {
		evaluation.add(ReasonPolicyDigestMismatch)
	}
	var scannerPolicy securityreport.Policy
	if !evaluation.json("security-policy", securityEvidence.Policy, ReasonMissingEvidence, &scannerPolicy) {
		evaluation.add(ReasonScannerFailed)
		return
	}
	scannerPolicy.Normalize()
	if err := scannerPolicy.Validate(); err != nil || !equalStrings(scannerPolicy.RequiredScanners, evaluation.policy.RequiredScanners) {
		evaluation.invalidate("security-policy", ReasonPolicyDigestMismatch)
		return
	}
	reports := make([]securityreport.Report, 0, len(securityEvidence.Reports))
	seen := make(map[string]struct{}, len(securityEvidence.Reports))
	for _, reportRef := range securityEvidence.Reports {
		id := "security-report:" + reportRef.ID
		var report securityreport.Report
		if !evaluation.json(id, reportRef.EvidenceRef, ReasonMissingEvidence, &report) {
			evaluation.add(ReasonScannerFailed)
			continue
		}
		report.Normalize()
		if err := report.Validate(); err != nil || report.Scanner.Name != reportRef.ID {
			evaluation.invalidate(id, ReasonScannerFailed)
			continue
		}
		seen[reportRef.ID] = struct{}{}
		reports = append(reports, report)
	}
	for _, required := range evaluation.policy.RequiredScanners {
		if _, exists := seen[required]; !exists {
			evaluation.add(ReasonScannerFailed)
		}
	}
	if len(seen) != len(evaluation.policy.RequiredScanners) {
		evaluation.add(ReasonScannerFailed)
	}
	evaluationTime, err := time.Parse(time.RFC3339, evaluation.manifest.EvaluationTime)
	if err != nil {
		evaluation.add(ReasonMalformedEvidence)
		return
	}
	calculated := securityreport.Evaluate(scannerPolicy, reports, evaluationTime)
	var recorded securityreport.Decision
	if !evaluation.json("security-decision", securityEvidence.Decision, ReasonMissingEvidence, &recorded) {
		evaluation.add(ReasonScannerFailed)
		return
	}
	if !reflect.DeepEqual(calculated, recorded) {
		evaluation.invalidate("security-decision", ReasonScannerFailed)
	}
	if calculated.Counts.AcceptedExceptions > evaluation.policy.MaxAcceptedExceptions {
		evaluation.add(ReasonVulnerabilityBlocking)
	}
	for _, reason := range calculated.ReasonCodes {
		switch reason {
		case securityreport.ReasonBlockingFinding, securityreport.ReasonProhibitedLicense:
			evaluation.add(ReasonVulnerabilityBlocking)
		case securityreport.ReasonExceptionExpired:
			evaluation.add(ReasonExceptionExpired)
		default:
			evaluation.add(ReasonScannerFailed)
		}
	}
}

func (evaluation *evaluator) verifyIntegrity() {
	if evaluation.archive.ManifestDigest == "" {
		evaluation.add(ReasonIntegrityInvalid)
		return
	}
	sbomBytes, ok := evaluation.document("sbom", evaluation.manifest.Integrity.SBOM, ReasonSBOMMissing)
	if ok {
		document, err := integrity.DecodeSPDX(bytes.NewReader(sbomBytes))
		if err != nil || integrity.VerifySPDX(document, evaluation.archive.ManifestDigest, evaluation.policy.Module, evaluation.policy.GoVersion) != nil {
			evaluation.invalidate("sbom", ReasonSBOMMissing)
		}
	}
	provenanceBytes, ok := evaluation.document("provenance", evaluation.manifest.Integrity.Provenance, ReasonProvenanceInvalid)
	if ok {
		statement, err := integrity.DecodeStatement(bytes.NewReader(provenanceBytes))
		expected := integrity.ProvenanceInput{
			SubjectName:     evaluation.manifest.Artifact.Name,
			SourceURI:       evaluation.manifest.Artifact.SourceURI,
			SourceDigest:    evaluation.manifest.Artifact.SourceDigest,
			BuildType:       evaluation.policy.ProvenanceBuildType,
			BuilderID:       evaluation.policy.ProvenanceBuilderID,
			InvocationID:    "local:" + evaluation.manifest.Artifact.SourceDigest,
			SourceDateEpoch: evaluation.policy.SourceDateEpoch,
		}
		if err != nil || integrity.VerifyProvenance(statement, evaluation.archive, expected) != nil {
			evaluation.invalidate("provenance", ReasonProvenanceInvalid)
		}
	}
	var verification integrityVerification
	if !evaluation.json("integrity-verification", evaluation.manifest.Integrity.Verification, ReasonMissingEvidence, &verification) {
		evaluation.add(ReasonIntegrityInvalid)
		return
	}
	if verification.SchemaVersion != SchemaVersion || !verification.Verified || verification.Subject.Name != evaluation.manifest.Artifact.Name ||
		verification.Subject.Digest["sha256"] != strings.TrimPrefix(evaluation.manifest.Artifact.ManifestDigest, "sha256:") ||
		verification.ArchiveSHA256 != evaluation.manifest.Artifact.Archive.SHA256 ||
		verification.SBOMSHA256 != evaluation.manifest.Integrity.SBOM.SHA256 ||
		verification.ProvenanceSHA256 != evaluation.manifest.Integrity.Provenance.SHA256 ||
		verification.Platform != evaluation.manifest.Artifact.Platform {
		evaluation.invalidate("integrity-verification", ReasonIntegrityInvalid)
	}
}

func (evaluation *evaluator) verifySigning() {
	signingEvidence := evaluation.manifest.Signing
	if signingEvidence.Policy.SHA256 != evaluation.policy.SigningPolicySHA256 {
		evaluation.add(ReasonPolicyDigestMismatch)
	}
	var identityPolicy signingpolicy.Policy
	if !evaluation.json("signing-policy", signingEvidence.Policy, ReasonSignatureMissing, &identityPolicy) {
		return
	}
	identityPolicy.Normalize()
	if err := identityPolicy.Validate(); err != nil {
		evaluation.invalidate("signing-policy", ReasonPolicyDigestMismatch)
		return
	}
	var signingDecision signingpolicy.Decision
	if !evaluation.json("signing-decision", signingEvidence.Decision, ReasonSignatureMissing, &signingDecision) {
		return
	}
	if !signingDecision.Eligible {
		evaluation.invalidate("signing-decision", ReasonSignatureMissing)
		return
	}
	if !validSigningIdentity(identityPolicy, signingDecision, evaluation.manifest.Artifact.SourceDigest) {
		evaluation.invalidate("signing-decision", ReasonWorkflowIdentityMismatch)
		return
	}
	var validation ValidationStatement
	if !evaluation.json("validation", evaluation.manifest.Validation, ReasonSignatureMissing, &validation) {
		evaluation.add(ReasonValidationMismatch)
	} else if !reflect.DeepEqual(validation, evaluation.manifest.ValidationStatement(signingDecision.Identity.WorkflowTrigger)) {
		evaluation.invalidate("validation", ReasonValidationMismatch)
	}
	artifactRefs := map[string]EvidenceRef{
		"oci-archive":         evaluation.manifest.Artifact.Archive,
		"spdx-sbom":           evaluation.manifest.Integrity.SBOM,
		"local-provenance":    evaluation.manifest.Integrity.Provenance,
		"validation-evidence": evaluation.manifest.Validation,
	}
	rules := make(map[string]signingpolicy.ArtifactRule, len(identityPolicy.RequiredArtifacts))
	for _, rule := range identityPolicy.RequiredArtifacts {
		rules[rule.Role] = rule
	}
	if len(rules) != len(artifactRefs) {
		evaluation.add(ReasonSignatureMissing)
	}
	requests := make([]SignatureRequest, 0, len(signingDecision.Artifacts))
	seen := make(map[string]struct{}, len(signingDecision.Artifacts))
	for _, artifact := range signingDecision.Artifacts {
		ref, expected := artifactRefs[artifact.Role]
		rule, ruleExists := rules[artifact.Role]
		if !expected || !ruleExists || artifact.Path != ref.Path || artifact.Path != rule.Path || artifact.Bundle != rule.Bundle ||
			artifact.SHA256 != ref.SHA256 || !validHex(artifact.BundleSHA256, 64) || !artifact.Verified {
			evaluation.add(ReasonArtifactDigestMismatch)
			continue
		}
		if _, duplicate := seen[artifact.Role]; duplicate {
			evaluation.add(ReasonSignatureInvalid)
			continue
		}
		seen[artifact.Role] = struct{}{}
		artifactPath, artifactOK := evaluation.path("signed-artifact:"+artifact.Role, ref, ReasonSignatureMissing)
		bundleRef := EvidenceRef{Path: artifact.Bundle, SHA256: artifact.BundleSHA256}
		bundlePath, bundleOK := evaluation.path("signature-bundle:"+artifact.Role, bundleRef, ReasonSignatureMissing)
		if !artifactOK || !bundleOK {
			continue
		}
		requests = append(requests, SignatureRequest{
			ArtifactPath:        artifactPath,
			BundlePath:          bundlePath,
			CertificateIdentity: identityPolicy.CertificateIdentity,
			Issuer:              identityPolicy.Issuer,
			WorkflowName:        identityPolicy.WorkflowName,
			Repository:          identityPolicy.Repository,
			WorkflowRef:         identityPolicy.WorkflowRef,
			WorkflowSHA:         evaluation.manifest.Artifact.SourceDigest,
			WorkflowTrigger:     signingDecision.Identity.WorkflowTrigger,
		})
	}
	if len(seen) != len(artifactRefs) || len(requests) != len(artifactRefs) {
		evaluation.add(ReasonSignatureMissing)
		return
	}
	if evaluation.verifier == nil {
		evaluation.add(ReasonToolUnavailable)
		return
	}
	version, err := evaluation.verifier.Version(evaluation.ctx)
	if err != nil {
		evaluation.add(ReasonToolUnavailable)
		return
	}
	if version != evaluation.policy.CosignVersion {
		evaluation.add(ReasonToolUnavailable)
		return
	}
	for _, request := range requests {
		if err := evaluation.verifier.Verify(evaluation.ctx, request); err != nil {
			evaluation.add(ReasonSignatureInvalid)
		}
	}
}

func validSigningIdentity(policy signingpolicy.Policy, decision signingpolicy.Decision, sourceSHA string) bool {
	identity := decision.Identity
	if decision.SchemaVersion != signingpolicy.SchemaVersion || !decision.Eligible || len(decision.ReasonCodes) != 0 {
		return false
	}
	if identity.Issuer != policy.Issuer || identity.CertificateIdentity != policy.CertificateIdentity || identity.Repository != policy.Repository ||
		identity.WorkflowName != policy.WorkflowName || identity.WorkflowRef != policy.WorkflowRef || identity.WorkflowSHA != sourceSHA {
		return false
	}
	for _, trigger := range policy.AllowedTriggers {
		if identity.WorkflowTrigger == trigger {
			return true
		}
	}
	return false
}

func (evaluation *evaluator) json(id string, ref EvidenceRef, missingReason string, destination any) bool {
	err := evaluation.store.ReadJSON(ref, destination)
	if err != nil {
		evaluation.storeFailure(id, ref, missingReason, err)
		return false
	}
	evaluation.record(id, ref, "verified")
	return true
}

func (evaluation *evaluator) document(id string, ref EvidenceRef, missingReason string) ([]byte, bool) {
	content, err := evaluation.store.ReadDocument(ref)
	if err != nil {
		evaluation.storeFailure(id, ref, missingReason, err)
		return nil, false
	}
	evaluation.record(id, ref, "verified")
	return content, true
}

func (evaluation *evaluator) path(id string, ref EvidenceRef, missingReason string) (string, bool) {
	path, err := evaluation.store.Path(ref)
	if err != nil {
		evaluation.storeFailure(id, ref, missingReason, err)
		return "", false
	}
	evaluation.record(id, ref, "verified")
	return path, true
}

func (evaluation *evaluator) storeFailure(id string, ref EvidenceRef, missingReason string, err error) {
	switch {
	case errors.Is(err, ErrEvidenceMissing):
		evaluation.add(missingReason)
		evaluation.record(id, ref, "missing")
	case errors.Is(err, ErrEvidenceHashMismatch):
		evaluation.add(ReasonEvidenceHashMismatch)
		evaluation.record(id, ref, "hash_mismatch")
	default:
		evaluation.add(ReasonMalformedEvidence)
		evaluation.record(id, ref, "invalid")
	}
}

func (evaluation *evaluator) invalidate(id, reason string) {
	evaluation.add(reason)
	summary := evaluation.evidence[id]
	summary.State = "invalid"
	evaluation.evidence[id] = summary
}

func (evaluation *evaluator) add(reason string) {
	evaluation.reasons[reason] = struct{}{}
}

func (evaluation *evaluator) record(id string, ref EvidenceRef, state string) {
	evaluation.evidence[id] = EvidenceSummary{ID: id, Path: ref.Path, SHA256: ref.SHA256, State: state}
}

func (evaluation *evaluator) decision() Decision {
	reasons := make([]string, 0, len(evaluation.reasons))
	for reason := range evaluation.reasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	evidence := make([]EvidenceSummary, 0, len(evaluation.evidence))
	for _, summary := range evaluation.evidence {
		evidence = append(evidence, summary)
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].ID < evidence[j].ID })
	return Decision{
		SchemaVersion:  SchemaVersion,
		PolicyVersion:  evaluation.policy.Version,
		PolicySHA256:   evaluation.policyHash,
		ManifestSHA256: evaluation.manifestHash,
		EvaluatedAt:    evaluation.manifest.EvaluationTime,
		Eligible:       len(reasons) == 0,
		ReasonCodes:    reasons,
		Artifact: DecisionArtifact{
			Name:           evaluation.manifest.Artifact.Name,
			ManifestDigest: evaluation.manifest.Artifact.ManifestDigest,
			ArchiveSHA256:  evaluation.manifest.Artifact.Archive.SHA256,
			SourceDigest:   evaluation.manifest.Artifact.SourceDigest,
			Platform:       evaluation.manifest.Artifact.Platform,
		},
		Evidence: evidence,
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func Explain(decision Decision) string {
	if decision.Eligible {
		return fmt.Sprintf("release eligible: %s@%s", decision.Artifact.Name, decision.Artifact.ManifestDigest)
	}
	return fmt.Sprintf("release ineligible: %s", strings.Join(decision.ReasonCodes, ", "))
}
