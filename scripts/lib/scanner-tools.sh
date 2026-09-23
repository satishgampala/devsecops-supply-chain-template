#!/bin/sh

# One reference source for execution and independent release verification.
GOSEC_IMAGE=$(jq -er '.scannerReferences["gosec"]' "$ROOT/policy/release-v1.json")
GOVULNCHECK_REFERENCE=$(jq -er '.scannerReferences["govulncheck"]' "$ROOT/policy/release-v1.json")
GITLEAKS_IMAGE=$(jq -er '.scannerReferences["gitleaks"]' "$ROOT/policy/release-v1.json")
ZIZMOR_IMAGE=$(jq -er '.scannerReferences["zizmor"]' "$ROOT/policy/release-v1.json")
OSV_IMAGE=$(jq -er '.scannerReferences["osv-scanner"]' "$ROOT/policy/release-v1.json")
TRIVY_IMAGE=$(jq -er '.scannerReferences["trivy-image"]' "$ROOT/policy/release-v1.json")
