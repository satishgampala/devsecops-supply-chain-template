package integrity

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectOCIArchive(t *testing.T) {
	path, manifestDigest := writeOCIArchive(t, archiveOptions{})
	info, err := InspectOCIArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ManifestDigest != manifestDigest {
		t.Fatalf("manifest digest = %q, want %q", info.ManifestDigest, manifestDigest)
	}
	if len(info.ArchiveSHA256) != 64 || info.OS != "linux" || info.Architecture != "amd64" {
		t.Fatalf("unexpected archive info: %#v", info)
	}
}

func TestInspectOCIArchiveRejectsInvalidEvidence(t *testing.T) {
	tests := []struct {
		name    string
		options archiveOptions
	}{
		{name: "wrong platform", options: archiveOptions{architecture: "arm64"}},
		{name: "tampered layer", options: archiveOptions{tamperLayer: true}},
		{name: "oversized layer", options: archiveOptions{oversizedLayer: true}},
		{name: "missing manifest", options: archiveOptions{omitManifest: true}},
		{name: "duplicate index", options: archiveOptions{duplicateIndex: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, _ := writeOCIArchive(t, test.options)
			if _, err := InspectOCIArchive(path); err == nil {
				t.Fatal("invalid OCI archive was accepted")
			}
		})
	}
}

type archiveOptions struct {
	architecture   string
	tamperLayer    bool
	oversizedLayer bool
	omitManifest   bool
	duplicateIndex bool
}

func writeOCIArchive(t *testing.T, options archiveOptions) (string, string) {
	t.Helper()
	directory, err := os.MkdirTemp(".", "oci-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	path := filepath.Join(directory, "image.oci.tar")
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("application-layer")
	configDescriptor := ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digestBytes(config), Size: int64(len(config))}
	layerDescriptor := ociDescriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestBytes(layer), Size: int64(len(layer))}
	if options.oversizedLayer {
		layerDescriptor.Size = maxOCILayerSize + 1
	}
	manifest := ociManifest{SchemaVersion: 2, MediaType: ociManifestMediaType, Config: configDescriptor, Layers: []ociDescriptor{layerDescriptor}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	architecture := options.architecture
	if architecture == "" {
		architecture = "amd64"
	}
	manifestDescriptor := ociDescriptor{
		MediaType: ociManifestMediaType,
		Digest:    digestBytes(manifestBytes),
		Size:      int64(len(manifestBytes)),
		Platform:  &ociPlatform{Architecture: architecture, OS: "linux"},
	}
	index := ociIndex{SchemaVersion: 2, MediaType: ociIndexMediaType, Manifests: []ociDescriptor{manifestDescriptor}}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	writeTarFixture(t, writer, "index.json", indexBytes)
	if options.duplicateIndex {
		writeTarFixture(t, writer, "index.json", indexBytes)
	}
	if !options.omitManifest {
		writeTarFixture(t, writer, descriptorEntry(manifestDescriptor.Digest), manifestBytes)
	}
	writeTarFixture(t, writer, descriptorEntry(configDescriptor.Digest), config)
	if options.tamperLayer {
		layer = []byte("tampered-layer!!")
	}
	writeTarFixture(t, writer, descriptorEntry(layerDescriptor.Digest), layer)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path, manifestDescriptor.Digest
}

func writeTarFixture(t *testing.T, writer *tar.Writer, name string, content []byte) {
	t.Helper()
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := bytes.NewReader(content).WriteTo(writer); err != nil {
		t.Fatal(err)
	}
}
