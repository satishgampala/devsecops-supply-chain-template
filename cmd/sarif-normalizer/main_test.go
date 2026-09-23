package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/securityreport"
)

func TestRunPreservesDatabaseMetadata(t *testing.T) {
	t.Chdir(t.TempDir())
	input := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test","properties":{"db_last_modified":"2026-09-23T00:00:00Z"}}},"results":[]}]}`
	if err := os.WriteFile("input.sarif", []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-scanner", "govulncheck", "-reference", "test", "-input", "input.sarif", "-output", "normalized.json", "-scanner-exit-code", "0"}
	for _, test := range []struct{ override, want string }{
		{"", "2026-09-23T00:00:00Z"},
		{"2026-09-23T01:00:00Z", "2026-09-23T01:00:00Z"},
	} {
		flags := append([]string(nil), args...)
		if test.override != "" {
			flags = append(flags, "-database-updated-at", test.override)
		}
		if err := run(flags); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile("normalized.json")
		if err != nil {
			t.Fatal(err)
		}
		var report securityreport.Report
		if err := json.Unmarshal(content, &report); err != nil {
			t.Fatal(err)
		}
		if report.DatabaseUpdatedAt != test.want {
			t.Fatalf("timestamp=%q want=%q", report.DatabaseUpdatedAt, test.want)
		}
	}
	if err := run(append(args, "-database-updated-at", "not-a-timestamp")); err == nil {
		t.Fatal("accepted malformed timestamp")
	}
}

func TestRunRejectsFailedInvocation(t *testing.T) {
	t.Chdir(t.TempDir())
	input := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[],"invocations":[{"executionSuccessful":false}]}]}`
	if err := os.WriteFile("input.sarif", []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-scanner", "gosec", "-reference", "test", "-input", "input.sarif", "-output", filepath.Join("reports", "result.json")}); err == nil {
		t.Fatal("accepted failed invocation")
	}
	if _, err := os.Stat("reports/result.json"); !os.IsNotExist(err) {
		t.Fatal("failed invocation wrote a report")
	}
}
