package securityreport

import (
	"strings"
	"testing"
	"time"
)

func TestPolicyValidate(t *testing.T) {
	policy := testPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Policy)
		want   string
	}{
		{
			name: "duplicate scanner",
			mutate: func(policy *Policy) {
				policy.RequiredScanners = []string{"source", "source"}
			},
			want: "duplicate required scanner",
		},
		{
			name: "conflicting license",
			mutate: func(policy *Policy) {
				policy.ProhibitedLicenses = []string{"MIT"}
			},
			want: "both allowed and prohibited",
		},
		{
			name: "wildcard exception",
			mutate: func(policy *Policy) {
				policy.Exceptions[0].Rule = "*"
			},
			want: "wildcard scope",
		},
		{
			name: "invalid expiry",
			mutate: func(policy *Policy) {
				policy.Exceptions[0].ExpiresOn = "tomorrow"
			},
			want: "YYYY-MM-DD",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testPolicy()
			test.mutate(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestExceptionExpiryUsesUTCDate(t *testing.T) {
	exception := testPolicy().Exceptions[0]
	if exception.Expired(time.Date(2026, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -7*60*60))) {
		t.Fatal("exception expired before its UTC expiry date ended")
	}
	if !exception.Expired(time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("exception remained active after expiry")
	}
}

func testPolicy() Policy {
	return Policy{
		SchemaVersion:      SchemaVersion,
		Version:            "test-v1",
		RequiredScanners:   []string{"source"},
		BlockingSeverities: []Severity{SeverityHigh, SeverityCritical},
		AllowedLicenses:    []string{"MIT"},
		ProhibitedLicenses: []string{"GPL-3.0-only"},
		Exceptions: []Exception{
			{
				ID:        "EX-001",
				Owner:     "security-maintainers",
				Reason:    "Temporary mitigation is independently verified.",
				Scanner:   "source",
				Rule:      "fixture/high-risk",
				Artifact:  "internal/example.go",
				ExpiresOn: "2027-01-01",
			},
		},
	}
}
