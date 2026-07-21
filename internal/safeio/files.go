package safeio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Open(path string) (*os.File, error) {
	root, relative, err := workingTreePath(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(relative)
	if err != nil {
		return nil, fmt.Errorf("open working-tree file: %w", err)
	}
	return file, nil
}

func Create(path string) (*os.File, error) {
	root, relative, err := workingTreePath(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(relative), 0o750); err != nil {
		return nil, fmt.Errorf("create working-tree directory: %w", err)
	}
	file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create working-tree file: %w", err)
	}
	return file, nil
}

func workingTreePath(path string) (*os.Root, string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, "", fmt.Errorf("get working directory: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve path: %w", err)
	}
	relative, err := filepath.Rel(workingDirectory, absolute)
	if err != nil {
		return nil, "", fmt.Errorf("make path relative: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path must remain inside the working tree")
	}
	root, err := os.OpenRoot(workingDirectory)
	if err != nil {
		return nil, "", fmt.Errorf("open working tree: %w", err)
	}
	return root, relative, nil
}
