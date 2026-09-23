#!/bin/sh

set -eu

unsigned=false
case "${1:-}" in
  '') [ "$#" -eq 0 ] || exit 2 ;;
  --unsigned) [ "$#" -eq 1 ] || exit 2; unsigned=true ;;
  *) printf '%s\n' 'usage: collect-release-evidence.sh [--unsigned]' >&2; exit 2 ;;
esac
WORKFLOW_TRIGGER=${WORKFLOW_TRIGGER:-}
if [ "$unsigned" = true ]; then
  case "$WORKFLOW_TRIGGER" in
    push|workflow_dispatch) ;;
    *) printf '%s\n' 'unsigned validation requires an allowed WORKFLOW_TRIGGER' >&2; exit 2 ;;
  esac
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
EVIDENCE_DIR=${EVIDENCE_DIR:-"$ROOT/.local/release-evidence"}
INTEGRITY_DIR=${INTEGRITY_DIR:-"$ROOT/dist"}
SECURITY_DIR=${SECURITY_DIR:-"$ROOT/.local/release-input/security"}
SIGNING_DIR=${SIGNING_DIR:-"$ROOT/.local/release-input/signing"}
TEST_SUMMARY=${TEST_SUMMARY:-"$ROOT/.local/release-input/tests.json"}
EVALUATION_TIME=${EVALUATION_TIME:-}
SOURCE_DIGEST=${SOURCE_DIGEST:-$(git -C "$ROOT" rev-parse HEAD)}

absolute_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$ROOT" "$1" ;;
  esac
}

canonical_inside() {
  candidate=$1
  kind=$2
  if [ "$kind" = directory ]; then
    [ -d "$candidate" ] || { printf 'required directory is missing: %s\n' "$candidate" >&2; exit 2; }
  else
    [ -f "$candidate" ] || { printf 'required file is missing: %s\n' "$candidate" >&2; exit 2; }
  fi
  resolved=$(realpath "$candidate")
  case "$resolved" in
    "$ROOT"/*) printf '%s\n' "$resolved" ;;
    *) printf 'path must resolve inside the working tree: %s\n' "$candidate" >&2; exit 2 ;;
  esac
}

EVIDENCE_DIR=$(absolute_path "$EVIDENCE_DIR")
INTEGRITY_DIR=$(absolute_path "$INTEGRITY_DIR")
SECURITY_DIR=$(absolute_path "$SECURITY_DIR")
SIGNING_DIR=$(absolute_path "$SIGNING_DIR")
TEST_SUMMARY=$(absolute_path "$TEST_SUMMARY")

EVIDENCE_DIR=$(canonical_inside "$EVIDENCE_DIR" directory)
INTEGRITY_DIR=$(canonical_inside "$INTEGRITY_DIR" directory)
SECURITY_DIR=$(canonical_inside "$SECURITY_DIR" directory)
if [ "$unsigned" = false ]; then
  SIGNING_DIR=$(canonical_inside "$SIGNING_DIR" directory)
fi
TEST_SUMMARY=$(canonical_inside "$TEST_SUMMARY" file)

if [ "$EVIDENCE_DIR" = "$INTEGRITY_DIR" ] || [ "$EVIDENCE_DIR" = "$SECURITY_DIR" ] || [ "$EVIDENCE_DIR" = "$SIGNING_DIR" ]; then
  printf '%s\n' 'evidence output must differ from every input directory' >&2
  exit 2
fi

if ! printf '%s' "$SOURCE_DIGEST" | grep --extended-regexp --quiet '^[0-9a-f]{40}$'; then
  printf '%s\n' 'SOURCE_DIGEST must be a full lowercase Git SHA' >&2
  exit 2
fi
if ! printf '%s' "$EVALUATION_TIME" | grep --extended-regexp --quiet '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
  printf '%s\n' 'EVALUATION_TIME must be explicit UTC RFC3339' >&2
  exit 2
fi

mkdir -p "$EVIDENCE_DIR/security-reports"
for name in \
  image.oci.tar image.spdx.raw.json provenance.local.json verification.json \
  tests.json security-policy.json security-decision.json signing-policy.json \
  signing-decision.json image.oci.sigstore.json image.spdx.sigstore.json \
  provenance.local.sigstore.json validation-evidence.json validation-evidence.sigstore.json release-evidence.json
do
  rm -f -- "$EVIDENCE_DIR/$name"
done

scanners='gitleaks gosec govulncheck osv-scanner trivy-config trivy-image trivy-license zizmor'
for scanner in $scanners
do
  rm -f -- "$EVIDENCE_DIR/security-reports/$scanner.json"
done

cp -- "$INTEGRITY_DIR/image.oci.tar" "$EVIDENCE_DIR/image.oci.tar"
cp -- "$INTEGRITY_DIR/image.spdx.raw.json" "$EVIDENCE_DIR/image.spdx.raw.json"
cp -- "$INTEGRITY_DIR/provenance.local.json" "$EVIDENCE_DIR/provenance.local.json"
cp -- "$INTEGRITY_DIR/verification.json" "$EVIDENCE_DIR/verification.json"
cp -- "$TEST_SUMMARY" "$EVIDENCE_DIR/tests.json"
cp -- "$ROOT/policy/security-policy.json" "$EVIDENCE_DIR/security-policy.json"
cp -- "$SECURITY_DIR/decision.json" "$EVIDENCE_DIR/security-decision.json"
cp -- "$ROOT/policy/signing-identity.json" "$EVIDENCE_DIR/signing-policy.json"
if [ "$unsigned" = false ]; then
  cp -- "$SIGNING_DIR/signing-decision.json" "$EVIDENCE_DIR/signing-decision.json"
  cp -- "$SIGNING_DIR/image.oci.sigstore.json" "$EVIDENCE_DIR/image.oci.sigstore.json"
  cp -- "$SIGNING_DIR/image.spdx.sigstore.json" "$EVIDENCE_DIR/image.spdx.sigstore.json"
  cp -- "$SIGNING_DIR/provenance.local.sigstore.json" "$EVIDENCE_DIR/provenance.local.sigstore.json"
  cp -- "$SIGNING_DIR/validation-evidence.json" "$EVIDENCE_DIR/validation-evidence.json"
  cp -- "$SIGNING_DIR/validation-evidence.sigstore.json" "$EVIDENCE_DIR/validation-evidence.sigstore.json"
fi
for scanner in $scanners
do
  cp -- "$SECURITY_DIR/normalized/$scanner.json" "$EVIDENCE_DIR/security-reports/$scanner.json"
done

hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
subject=$(cd "$ROOT" && go run ./cmd/supply-chain subject -artifact "$EVIDENCE_DIR/image.oci.tar")
reports=$(
  for scanner in $scanners
  do
    path="security-reports/$scanner.json"
    jq --null-input --arg id "$scanner" --arg path "$path" --arg sha "$(hash_file "$EVIDENCE_DIR/$path")" \
      '{id: $id, path: $path, sha256: $sha}'
  done | jq --slurp '.'
)

signing_decision_hash=''
validation_hash=''
manifest_output="$EVIDENCE_DIR/validation-evidence.json"
if [ "$unsigned" = false ]; then
  signing_decision_hash=$(hash_file "$EVIDENCE_DIR/signing-decision.json")
  validation_hash=$(hash_file "$EVIDENCE_DIR/validation-evidence.json")
  manifest_output="$EVIDENCE_DIR/release-evidence.json"
fi

jq --null-input \
  --arg unsigned "$unsigned" \
  --arg trigger "$WORKFLOW_TRIGGER" \
  --arg validation "$validation_hash" \
  --arg releasePolicy "$(hash_file "$ROOT/policy/release-v1.json")" \
  --arg evaluatedAt "$EVALUATION_TIME" \
  --arg name 'ghcr.io/satishgampala/devsecops-supply-chain-template' \
  --arg subject "$subject" \
  --arg archive "$(hash_file "$EVIDENCE_DIR/image.oci.tar")" \
  --arg sourceURI 'https://github.com/satishgampala/devsecops-supply-chain-template' \
  --arg sourceDigest "$SOURCE_DIGEST" \
  --arg tests "$(hash_file "$EVIDENCE_DIR/tests.json")" \
  --arg securityPolicy "$(hash_file "$EVIDENCE_DIR/security-policy.json")" \
  --arg securityDecision "$(hash_file "$EVIDENCE_DIR/security-decision.json")" \
  --arg sbom "$(hash_file "$EVIDENCE_DIR/image.spdx.raw.json")" \
  --arg provenance "$(hash_file "$EVIDENCE_DIR/provenance.local.json")" \
  --arg integrity "$(hash_file "$EVIDENCE_DIR/verification.json")" \
  --arg signingPolicy "$(hash_file "$EVIDENCE_DIR/signing-policy.json")" \
  --arg signingDecision "$signing_decision_hash" \
  --argjson reports "$reports" \
  '{
    schemaVersion: "1.0",
    releasePolicySHA256: $releasePolicy,
    evaluationTime: $evaluatedAt,
    artifact: {
      name: $name,
      manifestDigest: $subject,
      archive: {path: "image.oci.tar", sha256: $archive},
      sourceURI: $sourceURI,
      sourceDigest: $sourceDigest,
      platform: "linux/amd64"
    },
    tests: {path: "tests.json", sha256: $tests},
    security: {
      policy: {path: "security-policy.json", sha256: $securityPolicy},
      reports: $reports,
      decision: {path: "security-decision.json", sha256: $securityDecision}
    },
    integrity: {
      sbom: {path: "image.spdx.raw.json", sha256: $sbom},
      provenance: {path: "provenance.local.json", sha256: $provenance},
      verification: {path: "verification.json", sha256: $integrity}
    },
    signing: {
      policy: {path: "signing-policy.json", sha256: $signingPolicy},
      decision: {path: "signing-decision.json", sha256: $signingDecision}
    }
  } | if $unsigned == "true" then
    {schemaVersion, releasePolicySHA256, evaluationTime, artifact, tests, security, integrity,
     signingPolicy: .signing.policy, workflowTrigger: $trigger}
  else
    . + {validation: {path: "validation-evidence.json", sha256: $validation}}
  end' >"$manifest_output"

printf 'release evidence collected; subject=%s; output=%s\n' "$subject" "$EVIDENCE_DIR"
