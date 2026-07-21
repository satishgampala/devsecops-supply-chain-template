package securityreport

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Policy struct {
	SchemaVersion      string      `json:"schemaVersion"`
	Version            string      `json:"version"`
	RequiredScanners   []string    `json:"requiredScanners"`
	BlockingSeverities []Severity  `json:"blockingSeverities"`
	AllowedLicenses    []string    `json:"allowedLicenses"`
	ProhibitedLicenses []string    `json:"prohibitedLicenses"`
	Exceptions         []Exception `json:"exceptions"`
}

type Exception struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	Reason    string `json:"reason"`
	Scanner   string `json:"scanner"`
	Rule      string `json:"rule"`
	Artifact  string `json:"artifact"`
	ExpiresOn string `json:"expiresOn"`
}

func (policy *Policy) Normalize() {
	sort.Strings(policy.RequiredScanners)
	sort.Slice(policy.BlockingSeverities, func(i, j int) bool {
		return policy.BlockingSeverities[i].Rank() < policy.BlockingSeverities[j].Rank()
	})
	sort.Strings(policy.AllowedLicenses)
	sort.Strings(policy.ProhibitedLicenses)
	sort.Slice(policy.Exceptions, func(i, j int) bool {
		return policy.Exceptions[i].ID < policy.Exceptions[j].ID
	})
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported policy schema %q", policy.SchemaVersion)
	}
	if strings.TrimSpace(policy.Version) == "" {
		return fmt.Errorf("policy version is required")
	}
	if len(policy.RequiredScanners) == 0 {
		return fmt.Errorf("at least one required scanner is required")
	}
	if err := validateUniqueStrings("required scanner", policy.RequiredScanners); err != nil {
		return err
	}
	if len(policy.BlockingSeverities) == 0 {
		return fmt.Errorf("at least one blocking severity is required")
	}
	seenSeverity := make(map[Severity]struct{}, len(policy.BlockingSeverities))
	for _, severity := range policy.BlockingSeverities {
		if !severity.Valid() {
			return fmt.Errorf("invalid blocking severity %q", severity)
		}
		if _, exists := seenSeverity[severity]; exists {
			return fmt.Errorf("duplicate blocking severity %q", severity)
		}
		seenSeverity[severity] = struct{}{}
	}
	if err := validateUniqueStrings("allowed license", policy.AllowedLicenses); err != nil {
		return err
	}
	if err := validateUniqueStrings("prohibited license", policy.ProhibitedLicenses); err != nil {
		return err
	}
	allowed := stringSet(policy.AllowedLicenses)
	for _, license := range policy.ProhibitedLicenses {
		if _, exists := allowed[license]; exists {
			return fmt.Errorf("license %q is both allowed and prohibited", license)
		}
	}
	seenExceptions := make(map[string]struct{}, len(policy.Exceptions))
	for index, exception := range policy.Exceptions {
		if err := exception.Validate(); err != nil {
			return fmt.Errorf("exception %d: %w", index, err)
		}
		if _, exists := seenExceptions[exception.ID]; exists {
			return fmt.Errorf("duplicate exception id %q", exception.ID)
		}
		seenExceptions[exception.ID] = struct{}{}
	}
	return nil
}

func (exception Exception) Validate() error {
	fields := map[string]string{
		"id": exception.ID, "owner": exception.Owner, "reason": exception.Reason,
		"scanner": exception.Scanner, "rule": exception.Rule, "artifact": exception.Artifact,
		"expiresOn": exception.ExpiresOn,
	}
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if exception.Scanner == "*" || exception.Rule == "*" || exception.Artifact == "*" {
		return fmt.Errorf("wildcard scope is not allowed")
	}
	if _, err := time.Parse(time.DateOnly, exception.ExpiresOn); err != nil {
		return fmt.Errorf("expiresOn must use YYYY-MM-DD: %w", err)
	}
	return nil
}

func (exception Exception) Matches(finding Finding) bool {
	return exception.Scanner == finding.Scanner && exception.Rule == finding.Rule && exception.Artifact == finding.Artifact
}

func (exception Exception) Expired(now time.Time) bool {
	expires, err := time.Parse(time.DateOnly, exception.ExpiresOn)
	if err != nil {
		return true
	}
	today := now.UTC().Truncate(24 * time.Hour)
	return expires.Before(today)
}

func validateUniqueStrings(label string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s must be non-empty and trimmed", label)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate %s %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
