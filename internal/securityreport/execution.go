package securityreport

import "fmt"

// ValidateScannerExit distinguishes findings from execution failures for the
// exact scanner modes used by security-scan.sh. Gosec additionally requires its
// native JSON error summary because SARIF omits package-processing errors.
func ValidateScannerExit(report Report, code int) error {
	findingsCode := -1
	switch report.Scanner.Name {
	case "govulncheck", "zizmor": // SARIF mode reports findings with exit 0.
	case "gosec", "osv-scanner":
		findingsCode = 1
	case "gitleaks", "trivy-config", "trivy-image", "trivy-license":
		findingsCode = 10 // Explicitly configured, separate from tool errors.
	default:
		return fmt.Errorf("unsupported scanner execution contract %q", report.Scanner.Name)
	}
	if code == 0 || (code == findingsCode && len(report.Findings) > 0) {
		return nil
	}
	return fmt.Errorf("scanner %s failed with exit code %d", report.Scanner.Name, code)
}
