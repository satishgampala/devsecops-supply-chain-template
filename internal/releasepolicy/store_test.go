package releasepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreReadsVerifiedJSON(t *testing.T) {
	root := newStoreFixture(t)
	content := []byte(`{"schemaVersion":"1.0","sourceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tests":[]}`)
	writeStoreFixture(t, root, "nested/tests.json", content)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var summary TestSummary
	if err := store.ReadJSON(reference("nested/tests.json", content), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestStoreRejectsUnsafeEvidence(t *testing.T) {
	root := newStoreFixture(t)
	content := []byte(`{}`)
	writeStoreFixture(t, root, "evidence.json", content)
	outside := filepath.Join(root, "outside.json")
	writeStoreFixture(t, root, "outside.json", content)
	if err := os.Symlink("outside.json", filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tests := []EvidenceRef{
		{Path: "../outside.json", SHA256: strings.Repeat("a", 64)},
		{Path: "link.json", SHA256: reference(outside, content).SHA256},
		{Path: "evidence.json", SHA256: strings.Repeat("b", 64)},
	}
	for _, ref := range tests {
		if err := store.Verify(ref); err == nil {
			t.Fatalf("unsafe evidence accepted: %#v", ref)
		}
	}
}

func TestNewStoreRejectsSymlinkRoot(t *testing.T) {
	root := newStoreFixture(t)
	link := root + "-link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if _, err := NewStore(link); err == nil {
		t.Fatal("symlink evidence root was accepted")
	}
}

func newStoreFixture(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(".", "release-store-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	return strings.TrimPrefix(root, "."+string(filepath.Separator))
}

func writeStoreFixture(t *testing.T, root, path string, content []byte) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reference(path string, content []byte) EvidenceRef {
	digest := sha256.Sum256(content)
	return EvidenceRef{Path: path, SHA256: hex.EncodeToString(digest[:])}
}
