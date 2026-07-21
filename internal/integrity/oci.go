package integrity

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/safeio"
)

const (
	ociIndexMediaType    = "application/vnd.oci.image.index.v1+json"
	ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	maxOCIJSONSize       = 1 << 20
	maxOCILayerSize      = 1 << 30
	maxOCIArchiveSize    = 2 << 30
)

type ArchiveInfo struct {
	ManifestDigest string `json:"manifestDigest"`
	ArchiveSHA256  string `json:"archiveSHA256"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

type ociDescriptor struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      int64        `json:"size"`
	Platform  *ociPlatform `json:"platform,omitempty"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

func InspectOCIArchive(path string) (ArchiveInfo, error) {
	archiveHash, err := hashFile(path)
	if err != nil {
		return ArchiveInfo{}, err
	}
	indexBytes, err := readTarEntry(path, "index.json", maxOCIJSONSize)
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("read OCI index: %w", err)
	}
	var index ociIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return ArchiveInfo{}, fmt.Errorf("decode OCI index: %w", err)
	}
	if index.SchemaVersion != 2 || index.MediaType != ociIndexMediaType {
		return ArchiveInfo{}, fmt.Errorf("unsupported OCI index")
	}
	if len(index.Manifests) != 1 {
		return ArchiveInfo{}, fmt.Errorf("OCI index must contain exactly one manifest")
	}
	descriptor := index.Manifests[0]
	if descriptor.MediaType != ociManifestMediaType {
		return ArchiveInfo{}, fmt.Errorf("OCI index subject is not an image manifest")
	}
	if descriptor.Platform == nil || descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != "amd64" {
		return ArchiveInfo{}, fmt.Errorf("OCI image platform must be linux/amd64")
	}
	manifestBytes, err := readAndVerifyDescriptor(path, descriptor, maxOCIJSONSize)
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("verify OCI manifest: %w", err)
	}
	var manifest ociManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ArchiveInfo{}, fmt.Errorf("decode OCI manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != ociManifestMediaType {
		return ArchiveInfo{}, fmt.Errorf("unsupported OCI manifest")
	}
	if strings.TrimSpace(manifest.Config.MediaType) == "" {
		return ArchiveInfo{}, fmt.Errorf("OCI manifest config media type is required")
	}
	if _, err := readAndVerifyDescriptor(path, manifest.Config, maxOCIJSONSize); err != nil {
		return ArchiveInfo{}, fmt.Errorf("verify OCI config: %w", err)
	}
	if len(manifest.Layers) == 0 {
		return ArchiveInfo{}, fmt.Errorf("OCI manifest must contain at least one layer")
	}
	for index, layer := range manifest.Layers {
		if strings.TrimSpace(layer.MediaType) == "" {
			return ArchiveInfo{}, fmt.Errorf("OCI layer %d media type is required", index)
		}
		if err := verifyDescriptor(path, layer); err != nil {
			return ArchiveInfo{}, fmt.Errorf("verify OCI layer %d: %w", index, err)
		}
	}
	return ArchiveInfo{
		ManifestDigest: descriptor.Digest,
		ArchiveSHA256:  archiveHash,
		OS:             descriptor.Platform.OS,
		Architecture:   descriptor.Platform.Architecture,
	}, nil
}

func hashFile(path string) (string, error) {
	file, err := safeio.Open(path)
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat archive: %w", err)
	}
	if info.Size() < 0 || info.Size() > maxOCIArchiveSize {
		return "", fmt.Errorf("archive exceeds size limit")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash archive: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func HashFile(path string) (string, error) {
	return hashFile(path)
}

func readAndVerifyDescriptor(path string, descriptor ociDescriptor, limit int64) ([]byte, error) {
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}
	entry := descriptorEntry(descriptor.Digest)
	content, err := readTarEntry(path, entry, limit)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != descriptor.Size {
		return nil, fmt.Errorf("descriptor size mismatch")
	}
	if digestBytes(content) != descriptor.Digest {
		return nil, fmt.Errorf("descriptor digest mismatch")
	}
	return content, nil
}

func verifyDescriptor(path string, descriptor ociDescriptor) error {
	if err := validateDescriptor(descriptor); err != nil {
		return err
	}
	if descriptor.Size > maxOCILayerSize {
		return fmt.Errorf("descriptor exceeds layer size limit")
	}
	file, err := safeio.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	target := descriptorEntry(descriptor.Digest)
	reader := tar.NewReader(file)
	found := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		if header.Name != target {
			continue
		}
		if found {
			return fmt.Errorf("duplicate archive entry %q", target)
		}
		found = true
		if header.Size != descriptor.Size {
			return fmt.Errorf("descriptor size mismatch")
		}
		hash := sha256.New()
		written, err := io.CopyN(hash, reader, descriptor.Size)
		if err != nil {
			return fmt.Errorf("hash descriptor: %w", err)
		}
		if written != descriptor.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != descriptor.Digest {
			return fmt.Errorf("descriptor digest mismatch")
		}
	}
	if !found {
		return fmt.Errorf("archive entry %q is missing", target)
	}
	return nil
}

func readTarEntry(path, target string, limit int64) ([]byte, error) {
	file, err := safeio.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var content []byte
	found := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if header.Name != target {
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate archive entry %q", target)
		}
		found = true
		if header.Size < 0 || header.Size > limit {
			return nil, fmt.Errorf("archive entry %q exceeds size limit", target)
		}
		content, err = io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil {
			return nil, fmt.Errorf("read archive entry %q: %w", target, err)
		}
		if int64(len(content)) != header.Size {
			return nil, fmt.Errorf("archive entry %q is truncated", target)
		}
	}
	if !found {
		return nil, fmt.Errorf("archive entry %q is missing", target)
	}
	return content, nil
}

func validateDescriptor(descriptor ociDescriptor) error {
	if descriptor.Size < 0 {
		return fmt.Errorf("descriptor size is invalid")
	}
	if !validSHA256Digest(descriptor.Digest) {
		return fmt.Errorf("descriptor digest is invalid")
	}
	return nil
}

func descriptorEntry(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
