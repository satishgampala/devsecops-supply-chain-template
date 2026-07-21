package securityreport

import (
	"sort"
	"strings"
	"time"
)

const (
	ReasonRequiredScannerMissing = "required_scanner_missing"
	ReasonScannerFailed          = "scanner_failed"
	ReasonBlockingFinding        = "blocking_finding"
	ReasonProhibitedLicense      = "prohibited_license"
	ReasonExceptionInvalid       = "exception_invalid"
	ReasonExceptionExpired       = "exception_expired"
	ReasonReportInvalid          = "report_invalid"
)

type DecisionCounts struct {
	RequiredScanners   int `json:"requiredScanners"`
	Reports            int `json:"reports"`
	CompletedScanners  int `json:"completedScanners"`
	FailedScanners     int `json:"failedScanners"`
	Findings           int `json:"findings"`
	BlockingFindings   int `json:"blockingFindings"`
	AcceptedExceptions int `json:"acceptedExceptions"`
}

type Decision struct {
	SchemaVersion      string         `json:"schemaVersion"`
	PolicyVersion      string         `json:"policyVersion"`
	EvaluatedAt        string         `json:"evaluatedAt"`
	Eligible           bool           `json:"eligible"`
	ReasonCodes        []string       `json:"reasonCodes"`
	AcceptedExceptions []string       `json:"acceptedExceptions"`
	Counts             DecisionCounts `json:"counts"`
}

func Evaluate(policy Policy, reports []Report, now time.Time) Decision {
	reasons := make(map[string]struct{})
	accepted := make(map[string]struct{})
	decision := Decision{
		SchemaVersion:      SchemaVersion,
		PolicyVersion:      policy.Version,
		EvaluatedAt:        now.UTC().Format(time.RFC3339),
		ReasonCodes:        []string{},
		AcceptedExceptions: []string{},
		Counts: DecisionCounts{
			RequiredScanners: len(policy.RequiredScanners),
			Reports:          len(reports),
		},
	}
	if err := policy.Validate(); err != nil {
		if strings.Contains(err.Error(), "exception") {
			reasons[ReasonExceptionInvalid] = struct{}{}
		} else {
			reasons[ReasonReportInvalid] = struct{}{}
		}
		return finalizeDecision(decision, reasons, accepted)
	}

	for _, exception := range policy.Exceptions {
		if exception.Expired(now) {
			reasons[ReasonExceptionExpired] = struct{}{}
		}
	}

	reportByScanner := make(map[string]Report, len(reports))
	for _, report := range reports {
		if err := report.Validate(); err != nil {
			reasons[ReasonReportInvalid] = struct{}{}
			continue
		}
		if _, duplicate := reportByScanner[report.Scanner.Name]; duplicate {
			reasons[ReasonReportInvalid] = struct{}{}
			continue
		}
		reportByScanner[report.Scanner.Name] = report
		if report.State != ScannerCompleted {
			decision.Counts.FailedScanners++
			reasons[ReasonScannerFailed] = struct{}{}
			continue
		}
		decision.Counts.CompletedScanners++
		for _, finding := range report.Findings {
			decision.Counts.Findings++
			blocking := severityBlocked(policy.BlockingSeverities, finding.Severity)
			prohibitedLicense := licenseBlocked(policy, finding.License)
			if !blocking && !prohibitedLicense {
				continue
			}
			exception, matched := matchingException(policy.Exceptions, finding)
			if matched && !exception.Expired(now) {
				accepted[exception.ID] = struct{}{}
				continue
			}
			decision.Counts.BlockingFindings++
			if blocking {
				reasons[ReasonBlockingFinding] = struct{}{}
			}
			if prohibitedLicense {
				reasons[ReasonProhibitedLicense] = struct{}{}
			}
		}
	}

	for _, scanner := range policy.RequiredScanners {
		if _, exists := reportByScanner[scanner]; !exists {
			reasons[ReasonRequiredScannerMissing] = struct{}{}
		}
	}
	decision.Counts.AcceptedExceptions = len(accepted)
	return finalizeDecision(decision, reasons, accepted)
}

func severityBlocked(blocking []Severity, severity Severity) bool {
	for _, candidate := range blocking {
		if severity == candidate {
			return true
		}
	}
	return false
}

func licenseBlocked(policy Policy, license string) bool {
	if license == "" {
		return false
	}
	for _, prohibited := range policy.ProhibitedLicenses {
		if license == prohibited {
			return true
		}
	}
	for _, allowed := range policy.AllowedLicenses {
		if license == allowed {
			return false
		}
	}
	return true
}

func matchingException(exceptions []Exception, finding Finding) (Exception, bool) {
	for _, exception := range exceptions {
		if exception.Matches(finding) {
			return exception, true
		}
	}
	return Exception{}, false
}

func finalizeDecision(decision Decision, reasons, accepted map[string]struct{}) Decision {
	for reason := range reasons {
		decision.ReasonCodes = append(decision.ReasonCodes, reason)
	}
	for exception := range accepted {
		decision.AcceptedExceptions = append(decision.AcceptedExceptions, exception)
	}
	sort.Strings(decision.ReasonCodes)
	sort.Strings(decision.AcceptedExceptions)
	decision.Eligible = len(decision.ReasonCodes) == 0
	return decision
}
