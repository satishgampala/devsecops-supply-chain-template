package integrity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

type SPDXCreationInfo struct {
	Creators []string `json:"creators"`
	Created  string   `json:"created"`
}

type SPDXPackage struct {
	Name                  string         `json:"name"`
	SPDXID                string         `json:"SPDXID"`
	VersionInfo           string         `json:"versionInfo"`
	DownloadLocation      string         `json:"downloadLocation"`
	LicenseConcluded      string         `json:"licenseConcluded"`
	LicenseDeclared       string         `json:"licenseDeclared"`
	Checksums             []SPDXChecksum `json:"checksums"`
	PrimaryPackagePurpose string         `json:"primaryPackagePurpose"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

func DecodeSPDX(reader io.Reader) (SPDXDocument, error) {
	decoder := json.NewDecoder(reader)
	var document SPDXDocument
	if err := decoder.Decode(&document); err != nil {
		return SPDXDocument{}, fmt.Errorf("decode SPDX: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return SPDXDocument{}, fmt.Errorf("decode SPDX: unexpected trailing JSON value")
		}
		return SPDXDocument{}, fmt.Errorf("decode SPDX trailing data: %w", err)
	}
	return document, nil
}

func VerifySPDX(document SPDXDocument, manifestDigest, moduleName, goVersion string) error {
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" {
		return fmt.Errorf("unsupported SPDX document identity")
	}
	if strings.TrimSpace(document.Name) == "" {
		return fmt.Errorf("SPDX document name is required")
	}
	namespace, err := url.Parse(document.DocumentNamespace)
	if err != nil || namespace.Scheme != "https" || namespace.Host == "" {
		return fmt.Errorf("SPDX document namespace must be an absolute HTTPS URI")
	}
	if len(document.CreationInfo.Creators) == 0 {
		return fmt.Errorf("SPDX creator is required")
	}
	if _, err := time.Parse(time.RFC3339, document.CreationInfo.Created); err != nil {
		return fmt.Errorf("SPDX creation time is invalid")
	}
	if len(document.Packages) == 0 {
		return fmt.Errorf("SPDX package inventory is empty")
	}
	packages := make(map[string]SPDXPackage, len(document.Packages))
	moduleFound := false
	stdlibFound := false
	for index, pkg := range document.Packages {
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.SPDXID) == "" || strings.TrimSpace(pkg.VersionInfo) == "" {
			return fmt.Errorf("SPDX package %d is missing identity", index)
		}
		if pkg.DownloadLocation == "" || pkg.LicenseConcluded == "" || pkg.LicenseDeclared == "" {
			return fmt.Errorf("SPDX package %q is missing required metadata", pkg.SPDXID)
		}
		if _, duplicate := packages[pkg.SPDXID]; duplicate {
			return fmt.Errorf("duplicate SPDX package id %q", pkg.SPDXID)
		}
		packages[pkg.SPDXID] = pkg
		if pkg.Name == moduleName {
			moduleFound = true
		}
		if pkg.Name == "stdlib" && pkg.VersionInfo == goVersion {
			stdlibFound = true
		}
	}
	if !moduleFound {
		return fmt.Errorf("application module is absent from SPDX inventory")
	}
	if !stdlibFound {
		return fmt.Errorf("expected Go standard library is absent from SPDX inventory")
	}
	roots := append([]string(nil), document.DocumentDescribes...)
	for _, relationship := range document.Relationships {
		if relationship.SPDXElementID == document.SPDXID && relationship.RelationshipType == "DESCRIBES" {
			roots = append(roots, relationship.RelatedSPDXElement)
		}
	}
	roots = uniqueStrings(roots)
	if len(roots) != 1 {
		return fmt.Errorf("SPDX document must describe exactly one root package")
	}
	root, exists := packages[roots[0]]
	if !exists {
		return fmt.Errorf("SPDX root package is missing")
	}
	if root.PrimaryPackagePurpose != "CONTAINER" {
		return fmt.Errorf("SPDX root package is not a container")
	}
	if root.VersionInfo != manifestDigest {
		return fmt.Errorf("SPDX root version does not match OCI manifest digest")
	}
	wantChecksum := strings.TrimPrefix(manifestDigest, "sha256:")
	checksumFound := false
	for _, checksum := range root.Checksums {
		if checksum.Algorithm == "SHA256" && checksum.ChecksumValue == wantChecksum {
			checksumFound = true
		}
	}
	if !checksumFound {
		return fmt.Errorf("SPDX root checksum does not match OCI manifest digest")
	}
	return nil
}

func CanonicalizeSPDX(reader io.Reader) ([]byte, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SPDX for canonicalization: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode SPDX for canonicalization: trailing data")
	}
	delete(document, "documentNamespace")
	if creation, ok := document["creationInfo"].(map[string]any); ok {
		delete(creation, "created")
		sortStringArray(creation, "creators")
	}
	sortObjects(document, "packages", "SPDXID", "name", "versionInfo")
	if packages, ok := document["packages"].([]any); ok {
		for _, value := range packages {
			if pkg, ok := value.(map[string]any); ok {
				sortObjects(pkg, "checksums", "algorithm", "checksumValue")
				sortObjects(pkg, "externalRefs", "referenceCategory", "referenceType", "referenceLocator")
			}
		}
	}
	sortObjects(document, "files", "SPDXID", "fileName")
	if files, ok := document["files"].([]any); ok {
		for _, value := range files {
			if file, ok := value.(map[string]any); ok {
				sortObjects(file, "checksums", "algorithm", "checksumValue")
				sortStringArray(file, "fileTypes")
				sortStringArray(file, "licenseInfoInFiles")
			}
		}
	}
	sortObjects(document, "relationships", "spdxElementId", "relationshipType", "relatedSpdxElement")
	sortStringArray(document, "documentDescribes")
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode canonical SPDX: %w", err)
	}
	return output.Bytes(), nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortObjects(parent map[string]any, key string, fields ...string) {
	values, ok := parent[key].([]any)
	if !ok {
		return
	}
	sort.SliceStable(values, func(i, j int) bool {
		left, _ := values[i].(map[string]any)
		right, _ := values[j].(map[string]any)
		return objectKey(left, fields) < objectKey(right, fields)
	})
}

func objectKey(value map[string]any, fields []string) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, fmt.Sprint(value[field]))
	}
	return strings.Join(parts, "\x00")
}

func sortStringArray(parent map[string]any, key string) {
	values, ok := parent[key].([]any)
	if !ok {
		return
	}
	sort.SliceStable(values, func(i, j int) bool {
		return fmt.Sprint(values[i]) < fmt.Sprint(values[j])
	})
}
