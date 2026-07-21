package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRequiresInputs(t *testing.T) {
	code, err := run(nil, &bytes.Buffer{})
	if code != 2 || err == nil || !strings.Contains(err.Error(), "are required") {
		t.Fatalf("code = %d, error = %v", code, err)
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
