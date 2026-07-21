package releasepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxJSONSize     = 16 << 20
	maxEvidenceSize = 2 << 30
)

type Store struct {
	path string
	root *os.Root
}

func NewStore(path string) (*Store, error) {
	if !validRelativePath(path) {
		return nil, fmt.Errorf("evidence root must be a clean relative path")
	}
	workingTree, err := os.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("open working tree: %w", err)
	}
	defer workingTree.Close()
	if err := verifyComponents(workingTree, path, true); err != nil {
		return nil, fmt.Errorf("validate evidence root: %w", err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	return &Store{path: path, root: root}, nil
}

func (store *Store) Close() error {
	return store.root.Close()
}

func (store *Store) ReadJSON(ref EvidenceRef, destination any) error {
	content, err := store.read(ref, maxJSONSize)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode evidence JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode evidence JSON: trailing data")
	}
	return nil
}

func (store *Store) Verify(ref EvidenceRef) error {
	file, err := store.open(ref.Path, maxEvidenceSize)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash evidence: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
		return fmt.Errorf("evidence SHA-256 mismatch")
	}
	return nil
}

func (store *Store) Path(ref EvidenceRef) (string, error) {
	if err := store.Verify(ref); err != nil {
		return "", err
	}
	return filepath.Join(store.path, ref.Path), nil
}

func (store *Store) read(ref EvidenceRef, limit int64) ([]byte, error) {
	file, err := store.open(ref.Path, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != ref.SHA256 {
		return nil, fmt.Errorf("evidence SHA-256 mismatch")
	}
	return content, nil
}

func (store *Store) open(path string, limit int64) (*os.File, error) {
	if !validRelativePath(path) {
		return nil, fmt.Errorf("evidence path is unsafe")
	}
	if err := verifyComponents(store.root, path, false); err != nil {
		return nil, err
	}
	info, err := store.root.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat evidence: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence is not a regular file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("evidence exceeds size limit")
	}
	file, err := store.root.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence: %w", err)
	}
	return file, nil
}

func verifyComponents(root *os.Root, path string, finalDirectory bool) error {
	parts := strings.Split(filepath.ToSlash(path), "/")
	current := ""
	for index, part := range parts {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed")
		}
		isLast := index == len(parts)-1
		if !isLast && !info.IsDir() {
			return fmt.Errorf("non-directory path component")
		}
		if isLast && finalDirectory && !info.IsDir() {
			return fmt.Errorf("evidence root is not a directory")
		}
	}
	return nil
}
