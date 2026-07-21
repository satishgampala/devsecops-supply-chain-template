package securityreport

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const SchemaVersion = "1.0"

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityNote     Severity = "note"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type ScannerState string

const (
	ScannerCompleted ScannerState = "completed"
	ScannerFailed    ScannerState = "failed"
	ScannerNotRun    ScannerState = "not_run"
)

type Scanner struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
}

type Finding struct {
	Scanner     string   `json:"scanner"`
	Rule        string   `json:"rule"`
	Artifact    string   `json:"artifact"`
	Location    string   `json:"location"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation"`
	License     string   `json:"license,omitempty"`
}

type Report struct {
	SchemaVersion     string       `json:"schemaVersion"`
	Scanner           Scanner      `json:"scanner"`
	State             ScannerState `json:"state"`
	DatabaseUpdatedAt string       `json:"databaseUpdatedAt,omitempty"`
	Findings          []Finding    `json:"findings"`
	Diagnostic        string       `json:"diagnostic,omitempty"`
}

func DecodeStrict[T any](reader io.Reader) (T, error) {
	var value T
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return value, fmt.Errorf("unexpected trailing JSON value")
		}
		return value, fmt.Errorf("read trailing JSON: %w", err)
	}
	return value, nil
}

func Encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func (report *Report) Normalize() {
	if report.Findings == nil {
		report.Findings = []Finding{}
	}
	for index := range report.Findings {
		finding := &report.Findings[index]
		finding.Scanner = strings.TrimSpace(finding.Scanner)
		finding.Rule = strings.TrimSpace(finding.Rule)
		finding.Artifact = strings.TrimSpace(finding.Artifact)
		finding.Location = strings.TrimSpace(finding.Location)
		finding.Message = strings.TrimSpace(finding.Message)
		finding.Remediation = strings.TrimSpace(finding.Remediation)
		finding.License = strings.TrimSpace(finding.License)
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		left := report.Findings[i]
		right := report.Findings[j]
		leftKey := string(left.Severity) + "\x00" + left.Scanner + "\x00" + left.Rule + "\x00" + left.Artifact + "\x00" + left.Location + "\x00" + left.Message
		rightKey := string(right.Severity) + "\x00" + right.Scanner + "\x00" + right.Rule + "\x00" + right.Artifact + "\x00" + right.Location + "\x00" + right.Message
		return leftKey < rightKey
	})
}

func (report Report) Validate() error {
	if report.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported report schema %q", report.SchemaVersion)
	}
	if strings.TrimSpace(report.Scanner.Name) == "" {
		return fmt.Errorf("scanner name is required")
	}
	if strings.TrimSpace(report.Scanner.Reference) == "" {
		return fmt.Errorf("scanner reference is required")
	}
	switch report.State {
	case ScannerCompleted:
		if report.Diagnostic != "" {
			return fmt.Errorf("completed scanner must not contain a diagnostic")
		}
	case ScannerFailed, ScannerNotRun:
		if strings.TrimSpace(report.Diagnostic) == "" {
			return fmt.Errorf("scanner state %q requires a diagnostic", report.State)
		}
		if len(report.Findings) != 0 {
			return fmt.Errorf("scanner state %q must not contain findings", report.State)
		}
	default:
		return fmt.Errorf("unsupported scanner state %q", report.State)
	}
	for index, finding := range report.Findings {
		if finding.Scanner != report.Scanner.Name {
			return fmt.Errorf("finding %d scanner does not match report scanner", index)
		}
		if finding.Rule == "" || finding.Artifact == "" || finding.Location == "" || finding.Message == "" || finding.Remediation == "" {
			return fmt.Errorf("finding %d is missing a required field", index)
		}
		if !finding.Severity.Valid() {
			return fmt.Errorf("finding %d has invalid severity %q", index, finding.Severity)
		}
	}
	return nil
}

func (severity Severity) Valid() bool {
	switch severity {
	case SeverityUnknown, SeverityNote, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func (severity Severity) Rank() int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNote:
		return 1
	default:
		return 0
	}
}
