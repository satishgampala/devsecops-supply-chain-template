package securityreport

import (
	"reflect"
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 7, 21, 7, 0, 0, 0, time.UTC)
	clean := testReport("source", ScannerCompleted)
	high := testReport("source", ScannerCompleted)
	high.Findings = []Finding{testFinding("source", "fixture/high-risk", "internal/example.go", SeverityHigh, "")}
	license := testReport("source", ScannerCompleted)
	license.Findings = []Finding{testFinding("source", "license/GPL", "LICENSE", SeverityLow, "GPL-3.0-only")}
	failed := testReport("source", ScannerFailed)
	failed.Diagnostic = "scanner exited with status 2"

	tests := []struct {
		name    string
		policy  Policy
		reports []Report
		want    []string
		accept  []string
	}{
		{name: "clean", policy: policyWithoutExceptions(), reports: []Report{clean}, want: []string{}},
		{name: "missing", policy: policyWithoutExceptions(), reports: []Report{testReport("other", ScannerCompleted)}, want: []string{ReasonRequiredScannerMissing}},
		{name: "failed", policy: policyWithoutExceptions(), reports: []Report{failed}, want: []string{ReasonScannerFailed}},
		{name: "blocking", policy: policyWithoutExceptions(), reports: []Report{high}, want: []string{ReasonBlockingFinding}},
		{name: "license", policy: policyWithoutExceptions(), reports: []Report{license}, want: []string{ReasonProhibitedLicense}},
		{name: "accepted exception", policy: testPolicy(), reports: []Report{high}, want: []string{}, accept: []string{"EX-001"}},
		{
			name: "expired exception",
			policy: func() Policy {
				policy := testPolicy()
				policy.Exceptions[0].ExpiresOn = "2026-07-20"
				return policy
			}(),
			reports: []Report{high},
			want:    []string{ReasonBlockingFinding, ReasonExceptionExpired},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Evaluate(test.policy, test.reports, now)
			if !reflect.DeepEqual(decision.ReasonCodes, test.want) {
				t.Fatalf("reason codes = %#v, want %#v", decision.ReasonCodes, test.want)
			}
			if !reflect.DeepEqual(decision.AcceptedExceptions, nilToEmpty(test.accept)) {
				t.Fatalf("accepted exceptions = %#v, want %#v", decision.AcceptedExceptions, nilToEmpty(test.accept))
			}
			if decision.Eligible != (len(test.want) == 0) {
				t.Fatalf("eligible = %v with reasons %#v", decision.Eligible, decision.ReasonCodes)
			}
		})
	}
}

func TestEvaluateRejectsDuplicateReports(t *testing.T) {
	report := testReport("source", ScannerCompleted)
	decision := Evaluate(policyWithoutExceptions(), []Report{report, report}, time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC))
	if !reflect.DeepEqual(decision.ReasonCodes, []string{ReasonReportInvalid}) {
		t.Fatalf("reason codes = %#v", decision.ReasonCodes)
	}
}

func TestUnknownSeverityRequiresExplicitAcceptance(t *testing.T) {
	policy := policyWithoutExceptions()
	policy.BlockingSeverities = append(policy.BlockingSeverities, SeverityUnknown)
	report := testReport("source", ScannerCompleted)
	report.Findings = []Finding{testFinding("source", "unmapped-rule", "file", SeverityUnknown, "")}
	decision := Evaluate(policy, []Report{report}, time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC))
	if decision.Eligible || !reflect.DeepEqual(decision.ReasonCodes, []string{ReasonBlockingFinding}) {
		t.Fatalf("unknown severity passed: %#v", decision)
	}
}

func TestEvaluateClassifiesInvalidPolicy(t *testing.T) {
	now := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	report := testReport("source", ScannerCompleted)

	invalidPolicy := policyWithoutExceptions()
	invalidPolicy.Version = ""
	decision := Evaluate(invalidPolicy, []Report{report}, now)
	if !reflect.DeepEqual(decision.ReasonCodes, []string{ReasonReportInvalid}) {
		t.Fatalf("invalid policy reasons = %#v", decision.ReasonCodes)
	}

	invalidException := testPolicy()
	invalidException.Exceptions[0].Rule = "*"
	decision = Evaluate(invalidException, []Report{report}, now)
	if !reflect.DeepEqual(decision.ReasonCodes, []string{ReasonExceptionInvalid}) {
		t.Fatalf("invalid exception reasons = %#v", decision.ReasonCodes)
	}
}

func policyWithoutExceptions() Policy {
	policy := testPolicy()
	policy.Exceptions = []Exception{}
	return policy
}

func testReport(name string, state ScannerState) Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Scanner:       Scanner{Name: name, Reference: name + "@sha256:test"},
		State:         state,
		Findings:      []Finding{},
	}
}

func testFinding(scanner, rule, artifact string, severity Severity, license string) Finding {
	return Finding{
		Scanner:     scanner,
		Rule:        rule,
		Artifact:    artifact,
		Location:    artifact + ":1",
		Severity:    severity,
		Message:     "synthetic finding",
		Remediation: "remove the synthetic defect",
		License:     license,
	}
}

func nilToEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
