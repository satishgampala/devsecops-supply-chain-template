package releasepolicy

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/integrity"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
	"github.com/satishgampala/devsecops-supply-chain-template/internal/signingpolicy"
)

func TestEvaluateAcceptsCompleteVerifiedEvidence(t *testing.T) {
	fixture := newEvaluationFixture(t)
	verifier := &fakeSignatureVerifier{version: fixture.policy.CosignVersion}
	decision := fixture.evaluate(verifier)
	if !decision.Eligible || len(decision.ReasonCodes) != 0 {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if verifier.calls != 4 {
		t.Fatalf("signature calls = %d, want 4", verifier.calls)
	}
	if len(decision.Evidence) != 20 {
		t.Fatalf("evidence summaries = %d, want 20", len(decision.Evidence))
	}
}

func TestEvaluateRejectsRehashedTestEvidence(t *testing.T) {
	fixture := newEvaluationFixture(t)
	fixture.tests.Tests[0].Ref = "a different execution with no authenticated result"
	fixture.manifest.Tests = fixture.writeJSON("tests.json", fixture.tests)
	decision := fixture.evaluate(&fakeSignatureVerifier{version: fixture.policy.CosignVersion})
	if decision.Eligible || !hasReason(decision, ReasonValidationMismatch) {
		t.Fatalf("rewritten test evidence: eligible=%v, reasons=%v", decision.Eligible, decision.ReasonCodes)
	}
}

func TestEvaluateRejectsReportLaunderingAndResealedEvidence(t *testing.T) {
	fixture := newEvaluationFixture(t)
	fixture.securityReports[0].Findings = []securityreport.Finding{{
		Scanner: "gosec", Rule: "G999", Artifact: "main.go", Location: "main.go:1",
		Severity: securityreport.SeverityHigh, Message: "blocking fixture", Remediation: "fix source",
	}}
	fixture.refreshSecurity()
	fixture.refreshValidation()
	verifier := fixture.boundVerifier()
	if decision := fixture.evaluate(verifier); !hasReason(decision, ReasonVulnerabilityBlocking) {
		t.Fatalf("baseline must block: %v", decision.ReasonCodes)
	}

	// An attacker edits a report, recomputes the aggregate decision, and updates
	// every public checksum while preserving the original signed artifacts.
	fixture.securityReports[0].Findings = []securityreport.Finding{}
	fixture.refreshSecurity()
	if decision := fixture.evaluate(verifier); decision.Eligible || !hasReason(decision, ReasonValidationMismatch) {
		t.Fatalf("laundered report accepted: %v", decision.ReasonCodes)
	}

	// Rewriting the validation statement and signing observation must then fail
	// the independent signature boundary, even though all checksums agree.
	fixture.refreshValidation()
	if decision := fixture.evaluate(verifier); decision.Eligible || !hasReason(decision, ReasonSignatureInvalid) {
		t.Fatalf("rewritten authenticated statement accepted: %v", decision.ReasonCodes)
	}
}

func TestEvaluateRejectsValidationFromAnotherTrigger(t *testing.T) {
	fixture := newEvaluationFixture(t)
	fixture.signingDecision.Identity.WorkflowTrigger = "workflow_dispatch"
	fixture.manifest.Signing.Decision = fixture.writeJSON("signing-decision.json", fixture.signingDecision)
	decision := fixture.evaluate(fixture.boundVerifier())
	if decision.Eligible || !hasReason(decision, ReasonValidationMismatch) {
		t.Fatalf("validation trigger mismatch accepted: %v", decision.ReasonCodes)
	}
}

func TestEvaluateRejectsReleaseFailures(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*evaluationFixture)
	}{
		{name: "failed test", reason: ReasonRequiredTestFailed, mutate: func(value *evaluationFixture) {
			value.tests.Tests[0].State = "failed"
			value.manifest.Tests = value.writeJSON("tests.json", value.tests)
		}},
		{name: "tests from another image", reason: ReasonRequiredTestFailed, mutate: func(value *evaluationFixture) {
			value.tests.SubjectDigest = "sha256:" + strings.Repeat("0", 64)
			value.manifest.Tests = value.writeJSON("tests.json", value.tests)
		}},
		{name: "missing SBOM", reason: ReasonSBOMMissing, mutate: func(value *evaluationFixture) {
			value.manifest.Integrity.SBOM.Path = "missing.spdx.json"
		}},
		{name: "invalid provenance", reason: ReasonProvenanceInvalid, mutate: func(value *evaluationFixture) {
			value.manifest.Integrity.Provenance = value.writeBytes("provenance.local.json", []byte("{}\n"))
		}},
		{name: "blocking vulnerability", reason: ReasonVulnerabilityBlocking, mutate: func(value *evaluationFixture) {
			value.securityReports[0].Findings = []securityreport.Finding{{
				Scanner: "gosec", Rule: "G999", Artifact: "main.go", Location: "main.go:1", Severity: securityreport.SeverityHigh,
				Message: "synthetic blocking finding", Remediation: "remove fixture",
			}}
			value.refreshSecurity()
		}},
		{name: "expired exception", reason: ReasonExceptionExpired, mutate: func(value *evaluationFixture) {
			value.securityPolicy.Exceptions = []securityreport.Exception{{
				ID: "expired", Owner: "security@example.invalid", Reason: "test", Scanner: "gosec", Rule: "G999", Artifact: "main.go", ExpiresOn: "2026-07-20",
			}}
			value.refreshSecurity()
		}},
		{name: "scanner failure", reason: ReasonScannerFailed, mutate: func(value *evaluationFixture) {
			value.securityReports[0].State = securityreport.ScannerFailed
			value.securityReports[0].Diagnostic = "synthetic failure"
			value.refreshSecurity()
		}},
		{name: "artifact digest", reason: ReasonArtifactDigestMismatch, mutate: func(value *evaluationFixture) {
			value.manifest.Artifact.ManifestDigest = "sha256:" + strings.Repeat("9", 64)
		}},
		{name: "policy digest", reason: ReasonPolicyDigestMismatch, mutate: func(value *evaluationFixture) {
			value.policy.SigningPolicySHA256 = strings.Repeat("8", 64)
		}},
		{name: "release policy digest", reason: ReasonPolicyDigestMismatch, mutate: func(value *evaluationFixture) {
			value.manifest.ReleasePolicySHA256 = strings.Repeat("8", 64)
		}},
		{name: "evaluation time", reason: ReasonEvaluationTimeMismatch, mutate: func(value *evaluationFixture) {
			value.expectedTime = "2026-07-21T12:01:00Z"
		}},
		{name: "wrong identity", reason: ReasonWorkflowIdentityMismatch, mutate: func(value *evaluationFixture) {
			value.signingDecision.Identity.WorkflowRef = "refs/heads/feature"
			value.manifest.Signing.Decision = value.writeJSON("signing-decision.json", value.signingDecision)
		}},
		{name: "evidence hash", reason: ReasonEvidenceHashMismatch, mutate: func(value *evaluationFixture) {
			value.manifest.Tests.SHA256 = strings.Repeat("7", 64)
		}},
		{name: "missing signature", reason: ReasonSignatureMissing, mutate: func(value *evaluationFixture) {
			value.signingDecision.Artifacts[0].Bundle = "missing.sigstore.json"
			value.manifest.Signing.Decision = value.writeJSON("signing-decision.json", value.signingDecision)
		}},
		{name: "unsigned", reason: ReasonSignatureMissing, mutate: func(value *evaluationFixture) {
			value.signingDecision.Eligible = false
			value.signingDecision.ReasonCodes = []string{signingpolicy.ReasonCryptographicVerificationFailed}
			value.manifest.Signing.Decision = value.writeJSON("signing-decision.json", value.signingDecision)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvaluationFixture(t)
			test.mutate(fixture)
			decision := fixture.evaluate(&fakeSignatureVerifier{version: fixture.policy.CosignVersion})
			if decision.Eligible || !hasReason(decision, test.reason) {
				t.Fatalf("reason codes = %v, want %s", decision.ReasonCodes, test.reason)
			}
		})
	}
}

func TestEvaluateRejectsUnboundOrStaleScannerEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*securityreport.Report)
	}{
		{"wrong tool", func(r *securityreport.Report) { r.Scanner.Reference = "different@version" }},
		{"wrong source", func(r *securityreport.Report) { r.SourceDigest = strings.Repeat("b", 40) }},
		{"wrong image", func(r *securityreport.Report) { r.SubjectDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"missing scan time", func(r *securityreport.Report) { r.ScannedAt = "" }},
		{"stale report", func(r *securityreport.Report) { r.ScannedAt = "2026-07-20T11:59:59Z" }},
		{"future report", func(r *securityreport.Report) { r.ScannedAt = "2026-07-21T12:05:01Z" }},
		{"missing database time", func(r *securityreport.Report) { r.DatabaseUpdatedAt = "" }},
		{"stale database", func(r *securityreport.Report) { r.DatabaseUpdatedAt = "2026-07-07T11:59:59Z" }},
		{"future database", func(r *securityreport.Report) { r.DatabaseUpdatedAt = "2026-07-21T12:05:01Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvaluationFixture(t)
			fixture.policy.RequiredDatabaseTimestamps = []string{"gosec"}
			fixture.securityReports[0].DatabaseUpdatedAt = fixture.expectedTime
			test.mutate(&fixture.securityReports[0])
			fixture.refreshSecurity()
			fixture.refreshValidation()
			decision := fixture.evaluate(&fakeSignatureVerifier{version: fixture.policy.CosignVersion})
			if decision.Eligible || !hasReason(decision, ReasonScannerFailed) {
				t.Fatalf("invalid scanner context accepted: %v", decision.ReasonCodes)
			}
		})
	}
}

func TestEvaluateAcceptsExactFreshnessBoundaries(t *testing.T) {
	fixture := newEvaluationFixture(t)
	fixture.policy.RequiredDatabaseTimestamps = []string{"gosec"}
	fixture.securityReports[0].ScannedAt = "2026-07-20T12:00:00Z"
	fixture.securityReports[0].DatabaseUpdatedAt = "2026-07-07T12:00:00Z"
	fixture.refreshSecurity()
	fixture.refreshValidation()
	if decision := fixture.evaluate(&fakeSignatureVerifier{version: fixture.policy.CosignVersion}); !decision.Eligible {
		t.Fatalf("exact freshness boundaries rejected: %v", decision.ReasonCodes)
	}
}

func TestEvaluateRejectsUnavailableAndFailingCosign(t *testing.T) {
	tests := []struct {
		name     string
		verifier SignatureVerifier
		reason   string
	}{
		{name: "unavailable", verifier: &fakeSignatureVerifier{versionError: errors.New("missing")}, reason: ReasonToolUnavailable},
		{name: "wrong version", verifier: &fakeSignatureVerifier{version: "v0.0.0"}, reason: ReasonToolUnavailable},
		{name: "invalid signature", verifier: &fakeSignatureVerifier{version: "v3.1.2", verifyError: ErrSignatureVerification}, reason: ReasonSignatureInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvaluationFixture(t)
			decision := fixture.evaluate(test.verifier)
			if decision.Eligible || !hasReason(decision, test.reason) {
				t.Fatalf("reason codes = %v, want %s", decision.ReasonCodes, test.reason)
			}
		})
	}
}

type fakeSignatureVerifier struct {
	version      string
	versionError error
	verifyError  error
	calls        int
	boundHashes  map[string]string
}

func (verifier *fakeSignatureVerifier) Version(context.Context) (string, error) {
	return verifier.version, verifier.versionError
}

func (verifier *fakeSignatureVerifier) Verify(_ context.Context, request SignatureRequest) error {
	verifier.calls++
	if verifier.boundHashes != nil {
		content, err := os.ReadFile(request.ArtifactPath)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		if verifier.boundHashes[request.ArtifactPath] != hex.EncodeToString(digest[:]) {
			return ErrSignatureVerification
		}
	}
	return verifier.verifyError
}

// Pin accepted bytes before attacker mutations. This is a test double for the
// signature boundary, not evidence of real Sigstore cryptographic verification.
func (fixture *evaluationFixture) boundVerifier() *fakeSignatureVerifier {
	verifier := &fakeSignatureVerifier{version: fixture.policy.CosignVersion, boundHashes: make(map[string]string)}
	for _, artifact := range fixture.signingDecision.Artifacts {
		verifier.boundHashes[filepath.Join(fixture.root, artifact.Path)] = artifact.SHA256
	}
	return verifier
}

type evaluationFixture struct {
	t               *testing.T
	root            string
	policy          Policy
	manifest        Manifest
	tests           TestSummary
	signingDecision signingpolicy.Decision
	expectedTime    string
	securityPolicy  securityreport.Policy
	securityReports []securityreport.Report
}

func newEvaluationFixture(t *testing.T) *evaluationFixture {
	t.Helper()
	root := newStoreFixture(t)
	fixture := &evaluationFixture{t: t, root: root}
	sourceDigest := strings.Repeat("a", 40)
	evaluationTime := "2026-07-21T12:00:00Z"
	artifactName := "ghcr.io/example/service"
	sourceURI := "https://github.com/example/service"

	archiveRef, archiveInfo := fixture.writeOCIArchive("image.oci.tar")
	sbom := validSPDX(archiveInfo.ManifestDigest)
	sbomRef := fixture.writeJSON("image.spdx.raw.json", sbom)
	provenanceInput := integrity.ProvenanceInput{
		SubjectName:     artifactName,
		SourceURI:       sourceURI,
		SourceDigest:    sourceDigest,
		BuildType:       "https://github.com/example/service/buildtypes/container/v1",
		BuilderID:       "https://github.com/example/service/builders/local-v1",
		InvocationID:    "local:" + sourceDigest,
		SourceDateEpoch: 0,
	}
	provenance, err := integrity.GenerateProvenance(archiveInfo, provenanceInput)
	if err != nil {
		t.Fatal(err)
	}
	provenanceRef := fixture.writeJSON("provenance.local.json", provenance)
	integrityRef := fixture.writeJSON("verification.json", integrityVerification{
		SchemaVersion: SchemaVersion,
		Verified:      true,
		Subject: integrity.Subject{
			Name:   artifactName,
			Digest: map[string]string{"sha256": strings.TrimPrefix(archiveInfo.ManifestDigest, "sha256:")},
		},
		ArchiveSHA256:    archiveRef.SHA256,
		SBOMSHA256:       sbomRef.SHA256,
		ProvenanceSHA256: provenanceRef.SHA256,
		Platform:         "linux/amd64",
	})

	fixture.tests = TestSummary{
		SchemaVersion: SchemaVersion,
		SourceDigest:  sourceDigest,
		SubjectDigest: archiveInfo.ManifestDigest,
		Tests: []TestResult{
			{ID: "build", State: "passed", Ref: "make build"},
			{ID: "host", State: "passed", Ref: "make verify"},
		},
	}
	testsRef := fixture.writeJSON("tests.json", fixture.tests)

	securityPolicy := securityreport.Policy{
		SchemaVersion:      securityreport.SchemaVersion,
		Version:            "test-v1",
		RequiredScanners:   []string{"gosec", "zizmor"},
		BlockingSeverities: []securityreport.Severity{securityreport.SeverityMedium, securityreport.SeverityHigh, securityreport.SeverityCritical},
		AllowedLicenses:    []string{"Apache-2.0"},
		ProhibitedLicenses: []string{"GPL-3.0-only"},
		Exceptions:         []securityreport.Exception{},
	}
	securityPolicy.Normalize()
	fixture.securityPolicy = securityPolicy
	securityPolicyRef := fixture.writeJSON("security-policy.json", securityPolicy)
	reports := []securityreport.Report{
		cleanReport("gosec", "gosec@test"),
		cleanReport("zizmor", "zizmor@test"),
	}
	for index := range reports {
		reports[index].SourceDigest = sourceDigest
		reports[index].SubjectDigest = archiveInfo.ManifestDigest
		reports[index].ScannedAt = evaluationTime
	}
	fixture.securityReports = reports
	reportRefs := make([]ScannerRef, 0, len(reports))
	for _, report := range reports {
		reportRefs = append(reportRefs, ScannerRef{ID: report.Scanner.Name, EvidenceRef: fixture.writeJSON(report.Scanner.Name+".json", report)})
	}
	now, err := time.Parse(time.RFC3339, evaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	securityDecision := securityreport.Evaluate(securityPolicy, reports, now)
	securityDecisionRef := fixture.writeJSON("security-decision.json", securityDecision)

	signingPolicy := signingpolicy.Policy{
		SchemaVersion:       signingpolicy.SchemaVersion,
		Issuer:              "https://token.actions.githubusercontent.com",
		CertificateIdentity: "https://github.com/example/service/.github/workflows/signing.yml@refs/heads/main",
		Repository:          "example/service",
		WorkflowName:        "Signing",
		WorkflowRef:         "refs/heads/main",
		AllowedTriggers:     []string{"push", "workflow_dispatch"},
		RequiredArtifacts: []signingpolicy.ArtifactRule{
			{Role: "local-provenance", Path: provenanceRef.Path, Bundle: "provenance.local.sigstore.json"},
			{Role: "oci-archive", Path: archiveRef.Path, Bundle: "image.oci.sigstore.json"},
			{Role: "spdx-sbom", Path: sbomRef.Path, Bundle: "image.spdx.sigstore.json"},
			{Role: "validation-evidence", Path: "validation-evidence.json", Bundle: "validation-evidence.sigstore.json"},
		},
	}
	signingPolicy.Normalize()
	signingPolicyRef := fixture.writeJSON("signing-policy.json", signingPolicy)
	bundles := map[string]EvidenceRef{
		"local-provenance": fixture.writeBytes("provenance.local.sigstore.json", []byte("synthetic provenance bundle")),
		"oci-archive":      fixture.writeBytes("image.oci.sigstore.json", []byte("synthetic archive bundle")),
		"spdx-sbom":        fixture.writeBytes("image.spdx.sigstore.json", []byte("synthetic SBOM bundle")),
	}
	artifactRefs := map[string]EvidenceRef{
		"local-provenance": provenanceRef,
		"oci-archive":      archiveRef,
		"spdx-sbom":        sbomRef,
	}
	fixture.signingDecision = signingpolicy.Decision{
		SchemaVersion: signingpolicy.SchemaVersion,
		Eligible:      true,
		ReasonCodes:   []string{},
		Identity: signingpolicy.IdentitySummary{
			Issuer:              signingPolicy.Issuer,
			CertificateIdentity: signingPolicy.CertificateIdentity,
			Repository:          signingPolicy.Repository,
			WorkflowName:        signingPolicy.WorkflowName,
			WorkflowRef:         signingPolicy.WorkflowRef,
			WorkflowSHA:         sourceDigest,
			WorkflowTrigger:     "push",
		},
	}
	for _, rule := range signingPolicy.RequiredArtifacts {
		if rule.Role == "validation-evidence" {
			continue
		}
		artifact := artifactRefs[rule.Role]
		bundle := bundles[rule.Role]
		fixture.signingDecision.Artifacts = append(fixture.signingDecision.Artifacts, signingpolicy.ArtifactObservation{
			Role: rule.Role, Path: artifact.Path, SHA256: artifact.SHA256,
			Bundle: bundle.Path, BundleSHA256: bundle.SHA256, Verified: true,
		})
	}
	signingDecisionRef := fixture.writeJSON("signing-decision.json", fixture.signingDecision)

	fixture.policy = Policy{
		SchemaVersion:        SchemaVersion,
		Version:              "test-v1",
		ArtifactName:         artifactName,
		SourceURI:            sourceURI,
		Platform:             "linux/amd64",
		Module:               "github.com/example/service",
		GoVersion:            "go1.26.5",
		ProvenanceBuildType:  provenanceInput.BuildType,
		ProvenanceBuilderID:  provenanceInput.BuilderID,
		SecurityPolicySHA256: securityPolicyRef.SHA256,
		SigningPolicySHA256:  signingPolicyRef.SHA256,
		CosignVersion:        "v3.1.2",
		RequiredTests:        []string{"build", "host"},
		RequiredScanners:     []string{"gosec", "zizmor"},
		ScannerReferences:    map[string]string{"gosec": "gosec@test", "zizmor": "zizmor@test"},
		MaxReportAgeHours:    24, MaxDatabaseAgeHours: 336,
		RequiredDatabaseTimestamps: []string{},
	}
	fixture.policy.Normalize()
	fixture.manifest = Manifest{
		SchemaVersion:       SchemaVersion,
		ReleasePolicySHA256: strings.Repeat("f", 64),
		EvaluationTime:      evaluationTime,
		Artifact: Artifact{
			Name: artifactName, ManifestDigest: archiveInfo.ManifestDigest, Archive: archiveRef,
			SourceURI: sourceURI, SourceDigest: sourceDigest, Platform: "linux/amd64",
		},
		Tests: testsRef,
		Security: SecurityEvidence{
			Policy: securityPolicyRef, Reports: reportRefs, Decision: securityDecisionRef,
		},
		Integrity: IntegrityEvidence{SBOM: sbomRef, Provenance: provenanceRef, Verification: integrityRef},
		Signing:   SigningEvidence{Policy: signingPolicyRef, Decision: signingDecisionRef},
	}
	fixture.refreshValidation()
	fixture.expectedTime = evaluationTime
	return fixture
}

func (fixture *evaluationFixture) evaluate(verifier SignatureVerifier) Decision {
	fixture.t.Helper()
	store, err := NewStore(fixture.root)
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer store.Close()
	return Evaluate(context.Background(), fixture.policy, strings.Repeat("f", 64), fixture.manifest, strings.Repeat("e", 64), fixture.expectedTime, store, verifier)
}

func (fixture *evaluationFixture) refreshSecurity() {
	fixture.t.Helper()
	fixture.securityPolicy.Normalize()
	policyRef := fixture.writeJSON("security-policy.json", fixture.securityPolicy)
	fixture.policy.SecurityPolicySHA256 = policyRef.SHA256
	fixture.manifest.Security.Policy = policyRef
	fixture.manifest.Security.Reports = nil
	for _, report := range fixture.securityReports {
		ref := fixture.writeJSON(report.Scanner.Name+".json", report)
		fixture.manifest.Security.Reports = append(fixture.manifest.Security.Reports, ScannerRef{ID: report.Scanner.Name, EvidenceRef: ref})
	}
	now, err := time.Parse(time.RFC3339, fixture.manifest.EvaluationTime)
	if err != nil {
		fixture.t.Fatal(err)
	}
	decision := securityreport.Evaluate(fixture.securityPolicy, fixture.securityReports, now)
	fixture.manifest.Security.Decision = fixture.writeJSON("security-decision.json", decision)
}

// Produce a statement and observation without changing a verifier's previously
// captured trusted hashes. Rewriting these files cannot authorize new bytes.
func (fixture *evaluationFixture) refreshValidation() {
	fixture.t.Helper()
	statement := fixture.manifest.ValidationStatement(fixture.signingDecision.Identity.WorkflowTrigger)
	ref := fixture.writeJSON("validation-evidence.json", statement)
	fixture.manifest.Validation = ref
	bundle := fixture.writeBytes("validation-evidence.sigstore.json", []byte("synthetic validation bundle"))
	observation := signingpolicy.ArtifactObservation{
		Role: "validation-evidence", Path: ref.Path, SHA256: ref.SHA256,
		Bundle: bundle.Path, BundleSHA256: bundle.SHA256, Verified: true,
	}
	found := false
	for index, artifact := range fixture.signingDecision.Artifacts {
		if artifact.Role == observation.Role {
			fixture.signingDecision.Artifacts[index] = observation
			found = true
		}
	}
	if !found {
		fixture.signingDecision.Artifacts = append(fixture.signingDecision.Artifacts, observation)
	}
	fixture.manifest.Signing.Decision = fixture.writeJSON("signing-decision.json", fixture.signingDecision)
}

func (fixture *evaluationFixture) writeJSON(path string, value any) EvidenceRef {
	fixture.t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fixture.t.Fatal(err)
	}
	content = append(content, '\n')
	return fixture.writeBytes(path, content)
}

func (fixture *evaluationFixture) writeBytes(path string, content []byte) EvidenceRef {
	fixture.t.Helper()
	writeStoreFixture(fixture.t, fixture.root, path, content)
	digest := sha256.Sum256(content)
	return EvidenceRef{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func (fixture *evaluationFixture) writeOCIArchive(path string) (EvidenceRef, integrity.ArchiveInfo) {
	fixture.t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("application-layer")
	configDescriptor := testOCIDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digestContent(config), Size: int64(len(config))}
	layerDescriptor := testOCIDescriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestContent(layer), Size: int64(len(layer))}
	manifest := testOCIManifest{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: configDescriptor, Layers: []testOCIDescriptor{layerDescriptor}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		fixture.t.Fatal(err)
	}
	manifestDescriptor := testOCIDescriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: digestContent(manifestBytes), Size: int64(len(manifestBytes)),
		Platform: &testOCIPlatform{Architecture: "amd64", OS: "linux"},
	}
	indexBytes, err := json.Marshal(testOCIIndex{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []testOCIDescriptor{manifestDescriptor}})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fullPath := filepath.Join(fixture.root, path)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fixture.t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	writeTarEntry(fixture.t, writer, "index.json", indexBytes)
	writeTarEntry(fixture.t, writer, descriptorPath(manifestDescriptor.Digest), manifestBytes)
	writeTarEntry(fixture.t, writer, descriptorPath(configDescriptor.Digest), config)
	writeTarEntry(fixture.t, writer, descriptorPath(layerDescriptor.Digest), layer)
	if err := writer.Close(); err != nil {
		fixture.t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		fixture.t.Fatal(err)
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		fixture.t.Fatal(err)
	}
	ref := fixture.writeBytes(path, content)
	info, err := integrity.InspectOCIArchive(filepath.Join(fixture.root, path))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return ref, info
}

type testOCIIndex struct {
	SchemaVersion int                 `json:"schemaVersion"`
	MediaType     string              `json:"mediaType"`
	Manifests     []testOCIDescriptor `json:"manifests"`
}

type testOCIManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	MediaType     string              `json:"mediaType"`
	Config        testOCIDescriptor   `json:"config"`
	Layers        []testOCIDescriptor `json:"layers"`
}

type testOCIDescriptor struct {
	MediaType string           `json:"mediaType"`
	Digest    string           `json:"digest"`
	Size      int64            `json:"size"`
	Platform  *testOCIPlatform `json:"platform,omitempty"`
}

type testOCIPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

func validSPDX(manifestDigest string) integrity.SPDXDocument {
	root := integrity.SPDXPackage{
		Name: "/work/image.oci.tar", SPDXID: "SPDXRef-Root", VersionInfo: manifestDigest,
		DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION",
		Checksums:             []integrity.SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: strings.TrimPrefix(manifestDigest, "sha256:")}},
		PrimaryPackagePurpose: "CONTAINER",
	}
	application := integrity.SPDXPackage{
		Name: "github.com/example/service", SPDXID: "SPDXRef-App", VersionInfo: "UNKNOWN",
		DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "Apache-2.0",
	}
	stdlib := integrity.SPDXPackage{
		Name: "stdlib", SPDXID: "SPDXRef-Stdlib", VersionInfo: "go1.26.5",
		DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "BSD-3-Clause",
	}
	return integrity.SPDXDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "image",
		DocumentNamespace: "https://example.invalid/spdx/test", CreationInfo: integrity.SPDXCreationInfo{Creators: []string{"Tool: test"}, Created: "2026-07-21T12:00:00Z"},
		Packages:      []integrity.SPDXPackage{root, application, stdlib},
		Relationships: []integrity.SPDXRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelatedSPDXElement: root.SPDXID, RelationshipType: "DESCRIBES"}},
	}
}

func cleanReport(name, reference string) securityreport.Report {
	return securityreport.Report{
		SchemaVersion: securityreport.SchemaVersion,
		Scanner:       securityreport.Scanner{Name: name, Reference: reference},
		State:         securityreport.ScannerCompleted,
		Findings:      []securityreport.Finding{},
	}
}

func writeTarEntry(t *testing.T, writer *tar.Writer, name string, content []byte) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
}

func digestContent(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func descriptorPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func hasReason(decision Decision, expected string) bool {
	for _, reason := range decision.ReasonCodes {
		if reason == expected {
			return true
		}
	}
	return false
}
