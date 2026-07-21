package securityreport

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []sarifRule    `json:"rules"`
	Properties     map[string]any `json:"properties"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	HelpURI              string                 `json:"helpUri"`
	Help                 sarifMessage           `json:"help"`
	FullDescription      sarifMessage           `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
	Properties           map[string]any         `json:"properties"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  *int            `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func NormalizeSARIF(reader io.Reader, scanner Scanner) (Report, error) {
	decoder := json.NewDecoder(reader)
	var log sarifLog
	if err := decoder.Decode(&log); err != nil {
		return Report{}, fmt.Errorf("decode SARIF: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Report{}, fmt.Errorf("decode SARIF: unexpected trailing JSON value")
		}
		return Report{}, fmt.Errorf("decode SARIF trailing data: %w", err)
	}
	if log.Version != "2.1.0" {
		return Report{}, fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	if len(log.Runs) == 0 {
		return Report{}, fmt.Errorf("SARIF contains no runs")
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		Scanner:       scanner,
		State:         ScannerCompleted,
		Findings:      []Finding{},
	}
	for runIndex, run := range log.Runs {
		if strings.TrimSpace(run.Tool.Driver.Name) == "" {
			return Report{}, fmt.Errorf("SARIF run %d has no tool driver name", runIndex)
		}
		if report.DatabaseUpdatedAt == "" {
			if updated, ok := run.Tool.Driver.Properties["db_last_modified"].(string); ok {
				report.DatabaseUpdatedAt = strings.TrimSpace(updated)
			}
		}
		rules := make(map[string]sarifRule, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID != "" {
				rules[rule.ID] = rule
			}
		}
		for resultIndex, result := range run.Results {
			rule, ruleFound := rules[result.RuleID]
			if !ruleFound && result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = run.Tool.Driver.Rules[*result.RuleIndex]
				ruleFound = true
			}
			ruleID := strings.TrimSpace(result.RuleID)
			if ruleID == "" && ruleFound {
				ruleID = strings.TrimSpace(rule.ID)
			}
			if ruleID == "" {
				return Report{}, fmt.Errorf("SARIF run %d result %d has no rule id", runIndex, resultIndex)
			}
			message := strings.TrimSpace(result.Message.Text)
			if message == "" {
				return Report{}, fmt.Errorf("SARIF run %d result %d has no message", runIndex, resultIndex)
			}
			artifact, location := sarifResultLocation(result)
			remediation := sarifRemediation(rule, ruleFound)
			finding := Finding{
				Scanner:     scanner.Name,
				Rule:        ruleID,
				Artifact:    artifact,
				Location:    location,
				Severity:    sarifSeverity(result, rule, ruleFound),
				Message:     message,
				Remediation: remediation,
			}
			if strings.Contains(strings.ToLower(scanner.Name), "license") {
				finding.License = licenseFromRule(ruleID)
			}
			report.Findings = append(report.Findings, finding)
		}
	}
	report.Normalize()
	if err := report.Validate(); err != nil {
		return Report{}, fmt.Errorf("normalize SARIF: %w", err)
	}
	return report, nil
}

func sarifResultLocation(result sarifResult) (string, string) {
	if len(result.Locations) == 0 {
		return "repository", "repository"
	}
	physical := result.Locations[0].PhysicalLocation
	artifact := strings.TrimSpace(physical.ArtifactLocation.URI)
	if artifact == "" {
		artifact = "repository"
	}
	location := artifact
	if physical.Region.StartLine > 0 {
		location += ":" + strconv.Itoa(physical.Region.StartLine)
	}
	return artifact, location
}

func sarifRemediation(rule sarifRule, found bool) string {
	if found {
		if text := strings.TrimSpace(rule.Help.Text); text != "" {
			return text
		}
		if uri := strings.TrimSpace(rule.HelpURI); uri != "" {
			return "See " + uri
		}
		if text := strings.TrimSpace(rule.FullDescription.Text); text != "" {
			return text
		}
	}
	return "Review the scanner guidance for this rule."
}

func sarifSeverity(result sarifResult, rule sarifRule, ruleFound bool) Severity {
	for _, properties := range []map[string]any{result.Properties, rule.Properties} {
		for _, key := range []string{"security-severity", "severity", "zizmor/severity"} {
			if value, exists := properties[key]; exists {
				if severity, ok := severityFromProperty(value); ok {
					return severity
				}
			}
		}
		if tags, exists := properties["tags"]; exists {
			if severity, ok := severityFromTags(tags); ok {
				return severity
			}
		}
	}
	if severity, ok := severityFromLevel(result.Level); ok {
		return severity
	}
	if ruleFound {
		if severity, ok := severityFromLevel(rule.DefaultConfiguration.Level); ok {
			return severity
		}
	}
	return SeverityUnknown
}

func severityFromTags(value any) (Severity, bool) {
	switch tags := value.(type) {
	case []any:
		for _, tag := range tags {
			if severity, ok := severityFromProperty(tag); ok && severity != SeverityUnknown {
				return severity, true
			}
		}
	case []string:
		for _, tag := range tags {
			if severity, ok := severityFromProperty(tag); ok && severity != SeverityUnknown {
				return severity, true
			}
		}
	}
	return SeverityUnknown, false
}

func severityFromProperty(value any) (Severity, bool) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if score, err := strconv.ParseFloat(text, 64); err == nil {
		switch {
		case score >= 9:
			return SeverityCritical, true
		case score >= 7:
			return SeverityHigh, true
		case score >= 4:
			return SeverityMedium, true
		case score > 0:
			return SeverityLow, true
		default:
			return SeverityUnknown, true
		}
	}
	switch strings.ToLower(text) {
	case "critical":
		return SeverityCritical, true
	case "high", "error":
		return SeverityHigh, true
	case "medium", "moderate", "warning":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	case "note", "info", "informational":
		return SeverityNote, true
	case "unknown", "none":
		return SeverityUnknown, true
	default:
		return SeverityUnknown, false
	}
}

func severityFromLevel(level string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh, true
	case "warning":
		return SeverityMedium, true
	case "note":
		return SeverityLow, true
	case "none":
		return SeverityUnknown, true
	default:
		return SeverityUnknown, false
	}
}

func licenseFromRule(ruleID string) string {
	index := strings.LastIndex(ruleID, ":")
	if index == -1 || index == len(ruleID)-1 {
		return ""
	}
	return ruleID[index+1:]
}
