package safeio

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndOpenInsideWorkingTree(t *testing.T) {
	directory, err := os.MkdirTemp(".", "safeio-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary directory: %v", err)
		}
	})
	path := filepath.Join(directory, "nested", "report.json")
	file, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("evidence"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	content, err := io.ReadAll(opened)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "evidence" {
		t.Fatalf("content = %q", content)
	}
}

func TestRejectsPathOutsideWorkingTree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outside.json")
	if _, err := Create(path); err == nil {
		t.Fatal("outside path was accepted")
	}
}
