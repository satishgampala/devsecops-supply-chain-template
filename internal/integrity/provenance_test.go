package integrity

import "testing"

func TestGenerateAndVerifyProvenance(t *testing.T) {
	info := testArchiveInfo()
	input := testProvenanceInput()
	statement, err := GenerateProvenance(info, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProvenance(statement, info, input); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyProvenanceRejectsMismatches(t *testing.T) {
	info := testArchiveInfo()
	input := testProvenanceInput()
	tests := []struct {
		name   string
		mutate func(*Statement)
	}{
		{name: "predicate", mutate: func(statement *Statement) { statement.PredicateType = "https://example.invalid/predicate" }},
		{name: "subject", mutate: func(statement *Statement) {
			statement.Subject[0].Digest["sha256"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{name: "source", mutate: func(statement *Statement) {
			statement.Predicate.BuildDefinition.ExternalParameters.Source.URI = "https://example.invalid/other"
		}},
		{name: "builder", mutate: func(statement *Statement) {
			statement.Predicate.RunDetails.Builder.ID = "https://example.invalid/builder"
		}},
		{name: "invocation", mutate: func(statement *Statement) { statement.Predicate.RunDetails.Metadata.InvocationID = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement, err := GenerateProvenance(info, input)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&statement)
			if err := VerifyProvenance(statement, info, input); err == nil {
				t.Fatal("mismatched provenance was accepted")
			}
		})
	}
}

func testArchiveInfo() ArchiveInfo {
	return ArchiveInfo{
		ManifestDigest: testManifestDigest,
		ArchiveSHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OS:             "linux",
		Architecture:   "amd64",
	}
}

func testProvenanceInput() ProvenanceInput {
	return ProvenanceInput{
		SubjectName:     "ghcr.io/example/service",
		SourceURI:       "https://github.com/example/service",
		SourceDigest:    "cccccccccccccccccccccccccccccccccccccccc",
		BuildType:       "https://github.com/example/service/buildtypes/container/v1",
		BuilderID:       "https://github.com/example/service/builders/local-v1",
		InvocationID:    "local:cccccccccccccccccccccccccccccccccccccccc",
		SourceDateEpoch: 0,
	}
}
