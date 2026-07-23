package integrity

import (
	"bytes"
	"strings"
	"testing"
)

const testManifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestVerifySPDX(t *testing.T) {
	document := validSPDXDocument()
	if err := VerifySPDX(document, testManifestDigest, "example.invalid/service", "go1.26.5"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySPDXRejectsInvalidEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SPDXDocument)
	}{
		{name: "empty inventory", mutate: func(document *SPDXDocument) { document.Packages = nil }},
		{name: "duplicate id", mutate: func(document *SPDXDocument) { document.Packages[1].SPDXID = document.Packages[0].SPDXID }},
		{name: "missing stdlib", mutate: func(document *SPDXDocument) { document.Packages[1].Name = "other" }},
		{name: "wrong digest", mutate: func(document *SPDXDocument) {
			document.Packages[2].VersionInfo = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{name: "wrong root", mutate: func(document *SPDXDocument) { document.Relationships[0].RelatedSPDXElement = "SPDXRef-missing" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validSPDXDocument()
			test.mutate(&document)
			if err := VerifySPDX(document, testManifestDigest, "example.invalid/service", "go1.26.5"); err == nil {
				t.Fatal("invalid SPDX document was accepted")
			}
		})
	}
}

func TestCanonicalizeSPDXIgnoresExpectedNondeterminism(t *testing.T) {
	first := `{"spdxVersion":"SPDX-2.3","documentNamespace":"https://example.invalid/one","creationInfo":{"created":"2026-07-21T00:00:00Z","creators":["Tool: syft"]},"packages":[{"SPDXID":"SPDXRef-b","name":"b"},{"SPDXID":"SPDXRef-a","name":"a"}]}`
	second := `{"packages":[{"name":"a","SPDXID":"SPDXRef-a"},{"name":"b","SPDXID":"SPDXRef-b"}],"creationInfo":{"creators":["Tool: syft"],"created":"2026-07-22T00:00:00Z"},"documentNamespace":"https://example.invalid/two","spdxVersion":"SPDX-2.3"}`
	firstCanonical, err := CanonicalizeSPDX(strings.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	secondCanonical, err := CanonicalizeSPDX(strings.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstCanonical, secondCanonical) {
		t.Fatalf("canonical output differs:\n%s\n%s", firstCanonical, secondCanonical)
	}
}

func TestDecodeSPDXRejectsTrailingData(t *testing.T) {
	if _, err := DecodeSPDX(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("trailing SPDX data was accepted")
	}
}

func validSPDXDocument() SPDXDocument {
	return SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "image.oci.tar",
		DocumentNamespace: "https://example.invalid/spdx/test",
		CreationInfo: SPDXCreationInfo{
			Creators: []string{"Tool: syft-1.48.0"},
			Created:  "2026-07-21T00:00:00Z",
		},
		Packages: []SPDXPackage{
			{Name: "example.invalid/service", SPDXID: "SPDXRef-app", VersionInfo: "UNKNOWN", DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION"},
			{Name: "stdlib", SPDXID: "SPDXRef-stdlib", VersionInfo: "go1.26.5", DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "BSD-3-Clause"},
			{Name: "image.oci.tar", SPDXID: "SPDXRef-root", VersionInfo: testManifestDigest, DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", PrimaryPackagePurpose: "CONTAINER", Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: strings.TrimPrefix(testManifestDigest, "sha256:")}}},
		},
		Relationships: []SPDXRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelatedSPDXElement: "SPDXRef-root", RelationshipType: "DESCRIBES"}},
	}
}
