package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExecuteRequiresKnownCommand(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}} {
		if err := execute(arguments, &bytes.Buffer{}); err == nil || err.Error() != usage {
			t.Fatalf("execute(%v) error = %v, want usage", arguments, err)
		}
	}
}

func TestCommandsRejectMissingRequiredFlags(t *testing.T) {
	tests := []struct {
		arguments []string
		message   string
	}{
		{arguments: []string{"subject"}, message: "-artifact is required"},
		{arguments: []string{"canonicalize"}, message: "-input and -output are required"},
		{arguments: []string{"provenance"}, message: "-artifact and -output are required"},
		{arguments: []string{"verify"}, message: "-artifact, -sbom, -provenance"},
	}
	for _, test := range tests {
		err := execute(test.arguments, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("execute(%v) error = %v", test.arguments, err)
		}
	}
}

func TestAnyBlank(t *testing.T) {
	if anyBlank("one", "two") {
		t.Fatal("nonblank values reported blank")
	}
	if !anyBlank("one", " \t") {
		t.Fatal("blank value was accepted")
	}
}
