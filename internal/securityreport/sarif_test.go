package securityreport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeSARIFRejectsExecutionFailures(t *testing.T) {
	for _, invocation := range []string{
		`{"executionSuccessful":false}`,
		`{}`,
		`{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]}`,
		`{"executionSuccessful":true,"toolConfigurationNotifications":[{"level":"error"}]}`,
	} {
		input := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[],"invocations":[` + invocation + `]}]}`
		if _, err := NormalizeSARIF(strings.NewReader(input), Scanner{Name: "gosec", Reference: "test"}); err == nil {
			t.Fatalf("accepted failed invocation: %s", invocation)
		}
	}
}

func TestScannerExitContracts(t *testing.T) {
	for _, scanner := range []string{"gosec", "osv-scanner", "gitleaks", "trivy-config", "trivy-image", "trivy-license", "govulncheck", "zizmor"} {
		t.Run(scanner, func(t *testing.T) {
			report := testReport(scanner, ScannerCompleted)
			if err := ValidateScannerExit(report, 0); err != nil {
				t.Fatal(err)
			}
			for _, code := range []int{1, 2, 10, 127} {
				if err := ValidateScannerExit(report, code); err == nil {
					t.Fatalf("empty report accepted exit %d", code)
				}
			}
			report.Findings = []Finding{testFinding(scanner, "rule", "file", SeverityHigh, "")}
			want := 10
			switch scanner {
			case "gosec", "osv-scanner":
				want = 1
			case "govulncheck", "zizmor":
				want = 0
			}
			if err := ValidateScannerExit(report, want); err != nil {
				t.Fatal(err)
			}
			if err := ValidateScannerExit(report, 2); err == nil {
				t.Fatal("tool error accepted despite findings")
			}
		})
	}
}

func TestNormalizeSARIFClean(t *testing.T) {
	report := normalizeFixture(t, "clean.sarif", "source")
	if report.State != ScannerCompleted {
		t.Fatalf("state = %q, want %q", report.State, ScannerCompleted)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

func TestNormalizeSARIFBlockingFinding(t *testing.T) {
	report := normalizeFixture(t, "blocking.sarif", "source")
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.Severity != SeverityCritical {
		t.Fatalf("severity = %q, want %q", finding.Severity, SeverityCritical)
	}
	if finding.Artifact != "testdata/security/example.txt" || finding.Location != "testdata/security/example.txt:7" {
		t.Fatalf("unexpected location: artifact=%q location=%q", finding.Artifact, finding.Location)
	}
	if finding.Remediation != "See https://example.invalid/remediation/high-risk" {
		t.Fatalf("remediation = %q", finding.Remediation)
	}
}

func TestNormalizeSARIFRejectsMalformedInput(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "security", "sarif", "malformed.sarif")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := NormalizeSARIF(file, Scanner{Name: "source", Reference: "fixture@sha256:test"}); err == nil {
		t.Fatal("malformed SARIF was accepted")
	}
}

func TestNormalizedReportEncodingIsStable(t *testing.T) {
	report := normalizeFixture(t, "blocking.sarif", "source")
	var first bytes.Buffer
	var second bytes.Buffer
	if err := Encode(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := Encode(&second, report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("identical reports produced different JSON")
	}
}

func TestNormalizeSARIFExtractsLicense(t *testing.T) {
	input := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"module:GPL-3.0-only","properties":{"security-severity":"8.0"}}]}},"results":[{"ruleId":"module:GPL-3.0-only","message":{"text":"restricted license"}}]}]}`
	report, err := NormalizeSARIF(bytes.NewBufferString(input), Scanner{Name: "trivy-license", Reference: "trivy@sha256:test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Findings[0].License; got != "GPL-3.0-only" {
		t.Fatalf("license = %q, want GPL-3.0-only", got)
	}
}

func normalizeFixture(t *testing.T, name, scanner string) Report {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "security", "sarif", name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	report, err := NormalizeSARIF(file, Scanner{Name: scanner, Reference: "fixture@sha256:test"})
	if err != nil {
		t.Fatal(err)
	}
	return report
}
