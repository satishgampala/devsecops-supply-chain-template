package releasepolicy

import (
	"fmt"
	"strings"
	"testing"
)

func TestPolicyValidation(t *testing.T) {
	policy := testPolicy()
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "mutable artifact", mutate: func(value *Policy) { value.ArtifactName += ":latest" }},
		{name: "policy digest", mutate: func(value *Policy) { value.SigningPolicySHA256 = "bad" }},
		{name: "duplicate test", mutate: func(value *Policy) { value.RequiredTests = []string{"host", "host"} }},
		{name: "Cosign wildcard", mutate: func(value *Policy) { value.CosignVersion = "v3.*" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			test.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}

func TestManifestValidationRejectsUnsafeAndDuplicateReferences(t *testing.T) {
	manifest := testManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "mutable artifact", mutate: func(value *Manifest) { value.Artifact.Name += ":latest" }},
		{name: "traversal", mutate: func(value *Manifest) { value.Tests.Path = "../tests.json" }},
		{name: "absolute", mutate: func(value *Manifest) { value.Tests.Path = "/tmp/tests.json" }},
		{name: "duplicate path", mutate: func(value *Manifest) { value.Tests.Path = value.Artifact.Archive.Path }},
		{name: "duplicate scanner", mutate: func(value *Manifest) { value.Security.Reports[1].ID = value.Security.Reports[0].ID }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := testManifest()
			test.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func testPolicy() Policy {
	return Policy{
		SchemaVersion:        SchemaVersion,
		Version:              "test-v1",
		ArtifactName:         "ghcr.io/example/service",
		SourceURI:            "https://github.com/example/service",
		Platform:             "linux/amd64",
		Module:               "github.com/example/service",
		GoVersion:            "go1.26.5",
		ProvenanceBuildType:  "https://github.com/example/service/buildtypes/container/v1",
		ProvenanceBuilderID:  "https://github.com/example/service/builders/local-v1",
		SecurityPolicySHA256: strings.Repeat("a", 64),
		SigningPolicySHA256:  strings.Repeat("b", 64),
		CosignVersion:        "v3.1.2",
		RequiredTests:        []string{"build", "host"},
		RequiredScanners:     []string{"gosec", "zizmor"},
	}
}

func testManifest() Manifest {
	index := 0
	next := func(path string) EvidenceRef {
		index++
		return EvidenceRef{Path: path, SHA256: fmt.Sprintf("%064x", index)}
	}
	return Manifest{
		SchemaVersion:  SchemaVersion,
		EvaluationTime: "2026-07-21T12:00:00Z",
		Artifact: Artifact{
			Name:           "ghcr.io/example/service",
			ManifestDigest: "sha256:" + strings.Repeat("c", 64),
			Archive:        next("image.oci.tar"),
			SourceURI:      "https://github.com/example/service",
			SourceDigest:   strings.Repeat("d", 40),
			Platform:       "linux/amd64",
		},
		Tests: next("tests.json"),
		Security: SecurityEvidence{
			Policy: next("security-policy.json"),
			Reports: []ScannerRef{
				{ID: "gosec", EvidenceRef: next("gosec.json")},
				{ID: "zizmor", EvidenceRef: next("zizmor.json")},
			},
			Decision: next("security-decision.json"),
		},
		Integrity: IntegrityEvidence{
			SBOM:         next("image.spdx.json"),
			Provenance:   next("provenance.json"),
			Verification: next("integrity-verification.json"),
		},
		Signing: SigningEvidence{
			Policy:   next("signing-policy.json"),
			Decision: next("signing-decision.json"),
		},
	}
}
