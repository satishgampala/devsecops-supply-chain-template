package signingpolicy

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvaluateAcceptsExactIdentityAndArtifacts(t *testing.T) {
	policy := validPolicy()
	observation := validObservation()
	decision := Evaluate(policy, observation, observation.WorkflowSHA)
	if !decision.Eligible || len(decision.ReasonCodes) != 0 {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if decision.Artifacts[0].Role != "local-provenance" || decision.Artifacts[2].Role != "spdx-sbom" {
		t.Fatalf("artifacts not normalized: %#v", decision.Artifacts)
	}
}

func TestMixedCaseRepositoryPreservesExactIdentity(t *testing.T) {
	policy := validPolicy()
	policy.Repository = "ExampleOrg/Secure-Service"
	policy.CertificateIdentity = "https://github.com/" + policy.Repository + "/.github/workflows/signing.yml@refs/heads/main"
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	observation := validObservation()
	observation.Repository = policy.Repository
	observation.CertificateIdentity = policy.CertificateIdentity
	if decision := Evaluate(policy, observation, observation.WorkflowSHA); !decision.Eligible {
		t.Fatalf("exact mixed-case identity rejected: %v", decision.ReasonCodes)
	}
	observation.Repository = strings.ToLower(policy.Repository)
	if decision := Evaluate(policy, observation, observation.WorkflowSHA); decision.Eligible || !contains(decision.ReasonCodes, ReasonRepositoryMismatch) {
		t.Fatalf("case-altered identity accepted: %v", decision.ReasonCodes)
	}
}

func TestEvaluateRejectsEveryIdentityAndEvidenceMismatch(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*Observation)
	}{
		{name: "cryptography", reason: ReasonCryptographicVerificationFailed, mutate: func(value *Observation) { value.CryptographicVerification = false }},
		{name: "transparency log", reason: ReasonTransparencyLogMissing, mutate: func(value *Observation) { value.TransparencyLogVerified = false }},
		{name: "embedded SCT", reason: ReasonEmbeddedSCTMissing, mutate: func(value *Observation) { value.EmbeddedSCTVerified = false }},
		{name: "issuer", reason: ReasonIssuerMismatch, mutate: func(value *Observation) { value.Issuer = "https://issuer.example.invalid" }},
		{name: "identity", reason: ReasonCertificateIdentityMismatch, mutate: func(value *Observation) {
			value.CertificateIdentity = "https://github.com/example/other/.github/workflows/signing.yml@refs/heads/main"
		}},
		{name: "repository", reason: ReasonRepositoryMismatch, mutate: func(value *Observation) { value.Repository = "example/other" }},
		{name: "workflow", reason: ReasonWorkflowNameMismatch, mutate: func(value *Observation) { value.WorkflowName = "Other" }},
		{name: "ref", reason: ReasonWorkflowRefMismatch, mutate: func(value *Observation) { value.WorkflowRef = "refs/heads/feature" }},
		{name: "sha", reason: ReasonWorkflowSHAInvalid, mutate: func(value *Observation) { value.WorkflowSHA = "not-a-sha" }},
		{name: "schema", reason: ReasonObservationSchemaInvalid, mutate: func(value *Observation) { value.SchemaVersion = "2.0" }},
		{name: "pull request", reason: ReasonWorkflowTriggerDenied, mutate: func(value *Observation) { value.WorkflowTrigger = "pull_request" }},
		{name: "unknown role", reason: ReasonArtifactSetMismatch, mutate: func(value *Observation) { value.Artifacts[0].Role = "unknown" }},
		{name: "duplicate role", reason: ReasonArtifactSetMismatch, mutate: func(value *Observation) { value.Artifacts[1].Role = value.Artifacts[0].Role }},
		{name: "artifact digest", reason: ReasonArtifactDigestInvalid, mutate: func(value *Observation) { value.Artifacts[0].SHA256 = "bad" }},
		{name: "bundle digest", reason: ReasonBundleDigestInvalid, mutate: func(value *Observation) { value.Artifacts[0].BundleSHA256 = "bad" }},
		{name: "artifact verification", reason: ReasonArtifactVerificationFailed, mutate: func(value *Observation) { value.Artifacts[0].Verified = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservation()
			test.mutate(&observation)
			decision := Evaluate(validPolicy(), observation, strings.Repeat("a", 40))
			if decision.Eligible || !contains(decision.ReasonCodes, test.reason) {
				t.Fatalf("reason codes = %v, want %s", decision.ReasonCodes, test.reason)
			}
		})
	}
}

func TestPolicyValidationRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "wildcard identity", mutate: func(value *Policy) { value.CertificateIdentity += "*" }},
		{name: "untrusted trigger", mutate: func(value *Policy) { value.AllowedTriggers = []string{"pull_request"} }},
		{name: "duplicate trigger", mutate: func(value *Policy) { value.AllowedTriggers = []string{"push", "push"} }},
		{name: "duplicate artifact", mutate: func(value *Policy) { value.RequiredArtifacts[1].Role = value.RequiredArtifacts[0].Role }},
		{name: "artifact traversal", mutate: func(value *Policy) { value.RequiredArtifacts[0].Path = "../artifact" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("unsafe policy was accepted")
			}
		})
	}
}

func TestEvaluateRejectsUnexpectedWorkflowSHA(t *testing.T) {
	observation := validObservation()
	decision := Evaluate(validPolicy(), observation, strings.Repeat("2", 40))
	if decision.Eligible || !contains(decision.ReasonCodes, ReasonWorkflowSHAMismatch) {
		t.Fatalf("reason codes = %v", decision.ReasonCodes)
	}
}

func TestDecodeStrictRejectsUnknownAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"schemaVersion":"1.0","unknown":true}`,
		`{"schemaVersion":"1.0"} {}`,
	} {
		if _, err := DecodeStrict[Policy](strings.NewReader(input)); err == nil {
			t.Fatalf("invalid input accepted: %s", input)
		}
	}
}

func TestDecodeStrictRejectsOversizedJSON(t *testing.T) {
	input := strings.NewReader(`{"schemaVersion":"1.0","workflowName":"` + strings.Repeat("a", maxSigningJSONSize) + `"}`)
	if _, err := DecodeStrict[Policy](input); err == nil {
		t.Fatal("oversized JSON was accepted")
	}
}

func TestDecisionEncodingIsStable(t *testing.T) {
	observation := validObservation()
	decision := Evaluate(validPolicy(), observation, observation.WorkflowSHA)
	var first bytes.Buffer
	var second bytes.Buffer
	if err := Encode(&first, decision); err != nil {
		t.Fatal(err)
	}
	if err := Encode(&second, decision); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("decision encoding changed")
	}
}

func validPolicy() Policy {
	return Policy{
		SchemaVersion:       SchemaVersion,
		Issuer:              "https://token.actions.githubusercontent.com",
		CertificateIdentity: "https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main",
		Repository:          "satishgampala/devsecops-supply-chain-template",
		WorkflowName:        "Signing",
		WorkflowRef:         "refs/heads/main",
		AllowedTriggers:     []string{"push", "workflow_dispatch"},
		RequiredArtifacts: []ArtifactRule{
			{Role: "local-provenance", Path: "provenance.local.json", Bundle: "provenance.local.sigstore.json"},
			{Role: "oci-archive", Path: "image.oci.tar", Bundle: "image.oci.sigstore.json"},
			{Role: "spdx-sbom", Path: "image.spdx.raw.json", Bundle: "image.spdx.sigstore.json"},
		},
	}
}

func validObservation() Observation {
	return Observation{
		SchemaVersion:             SchemaVersion,
		Issuer:                    "https://token.actions.githubusercontent.com",
		CertificateIdentity:       "https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main",
		Repository:                "satishgampala/devsecops-supply-chain-template",
		WorkflowName:              "Signing",
		WorkflowRef:               "refs/heads/main",
		WorkflowSHA:               strings.Repeat("a", 40),
		WorkflowTrigger:           "push",
		CryptographicVerification: true,
		TransparencyLogVerified:   true,
		EmbeddedSCTVerified:       true,
		Artifacts: []ArtifactObservation{
			{Role: "spdx-sbom", Path: "image.spdx.raw.json", SHA256: strings.Repeat("b", 64), Bundle: "image.spdx.sigstore.json", BundleSHA256: strings.Repeat("c", 64), Verified: true},
			{Role: "local-provenance", Path: "provenance.local.json", SHA256: strings.Repeat("d", 64), Bundle: "provenance.local.sigstore.json", BundleSHA256: strings.Repeat("e", 64), Verified: true},
			{Role: "oci-archive", Path: "image.oci.tar", SHA256: strings.Repeat("f", 64), Bundle: "image.oci.sigstore.json", BundleSHA256: strings.Repeat("1", 64), Verified: true},
		},
	}
}
