#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE_DIR=${RELEASE_FIXTURE_DIR:-"$ROOT/.local/release-fixtures"}
INPUT_DIR="$BASE_DIR/input"
SECURITY_DIR="$INPUT_DIR/security"
SIGNING_DIR="$INPUT_DIR/signing"
EVIDENCE_DIR="$BASE_DIR/evidence"
DECISION_DIR="$BASE_DIR/decisions"
EVALUATION_TIME=${EVALUATION_TIME:-2026-07-21T12:00:00Z}
SOURCE_DIGEST=$(git -C "$ROOT" rev-parse HEAD)

case "$BASE_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'RELEASE_FIXTURE_DIR must remain inside the working tree' >&2; exit 2 ;;
esac
case "$BASE_DIR" in
  *'/../'*|*'/./'*|*/..|*/.) printf '%s\n' 'RELEASE_FIXTURE_DIR must be a clean path' >&2; exit 2 ;;
esac
if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]; then
  printf '%s\n' 'release fixtures require a clean working tree' >&2
  exit 2
fi

mkdir -p "$SECURITY_DIR/normalized" "$SIGNING_DIR" "$EVIDENCE_DIR" "$DECISION_DIR" "$BASE_DIR/bin"
cp -- "$ROOT/testdata/release/fake-cosign.sh" "$BASE_DIR/bin/cosign"
chmod 700 "$BASE_DIR/bin/cosign"
PATH="$BASE_DIR/bin:$PATH"
export PATH
for name in clean missing-sbom signature-invalid policy-mismatch time-mismatch rehashed-tests rewritten-validation
do
  rm -f -- "$DECISION_DIR/$name.json"
done

cd "$ROOT"
make integrity
subject=$(go run ./cmd/supply-chain subject -artifact dist/image.oci.tar)

scanners='gitleaks gosec govulncheck osv-scanner trivy-config trivy-image trivy-license zizmor'
set --
for scanner in $scanners
do
  reference=$(jq -er --arg scanner "$scanner" '.scannerReferences[$scanner]' policy/release-v1.json)
  jq --null-input --arg scanner "$scanner" --arg reference "$reference" \
    --arg source "$SOURCE_DIGEST" --arg subject "$subject" --arg time "$EVALUATION_TIME" \
    '{schemaVersion:"1.0",scanner:{name:$scanner,reference:$reference},sourceDigest:$source,
      subjectDigest:$subject,scannedAt:$time,databaseUpdatedAt:$time,state:"completed",findings:[]}'  \
    >"$SECURITY_DIR/normalized/$scanner.json"
  set -- "$@" -report "$SECURITY_DIR/normalized/$scanner.json"
done
go run ./cmd/security-gate \
  -policy policy/security-policy.json \
  -evaluation-time "$EVALUATION_TIME" \
  -output "$SECURITY_DIR/decision.json" \
  "$@"

jq --null-input --arg source "$SOURCE_DIGEST" --arg subject "$subject" \
  '{schemaVersion:"1.0",sourceDigest:$source,subjectDigest:$subject,tests:[
    {id:"build",state:"passed",ref:"make build"},
    {id:"container-smoke",state:"passed",ref:"make container-smoke"},
    {id:"host",state:"passed",ref:"make verify"},
    {id:"integrity",state:"passed",ref:"make integrity"},
    {id:"race",state:"passed",ref:"make test-race"},
    {id:"security-fixtures",state:"passed",ref:"make security-fixtures"}
  ]}' >"$INPUT_DIR/tests.json"

mkdir -p "$BASE_DIR/unsigned"
EVIDENCE_DIR="$BASE_DIR/unsigned" \
INTEGRITY_DIR="$ROOT/dist" \
SECURITY_DIR="$SECURITY_DIR" \
TEST_SUMMARY="$INPUT_DIR/tests.json" \
EVALUATION_TIME="$EVALUATION_TIME" \
SOURCE_DIGEST="$SOURCE_DIGEST" \
WORKFLOW_TRIGGER=push \
  ./scripts/collect-release-evidence.sh --unsigned
cp -- "$BASE_DIR/unsigned/validation-evidence.json" "$SIGNING_DIR/validation-evidence.json"
printf '%s\n' 'synthetic validation bundle; cryptography is replaced only by the fixture verifier' >"$SIGNING_DIR/validation-evidence.sigstore.json"

printf '%s\n' 'synthetic OCI bundle; cryptography is replaced only by the fixture verifier' >"$SIGNING_DIR/image.oci.sigstore.json"
printf '%s\n' 'synthetic SPDX bundle; cryptography is replaced only by the fixture verifier' >"$SIGNING_DIR/image.spdx.sigstore.json"
printf '%s\n' 'synthetic provenance bundle; cryptography is replaced only by the fixture verifier' >"$SIGNING_DIR/provenance.local.sigstore.json"

hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
jq --null-input \
  --arg source "$SOURCE_DIGEST" \
  --arg archive "$(hash_file dist/image.oci.tar)" \
  --arg archiveBundle "$(hash_file "$SIGNING_DIR/image.oci.sigstore.json")" \
  --arg sbom "$(hash_file dist/image.spdx.raw.json)" \
  --arg sbomBundle "$(hash_file "$SIGNING_DIR/image.spdx.sigstore.json")" \
  --arg provenance "$(hash_file dist/provenance.local.json)" \
  --arg provenanceBundle "$(hash_file "$SIGNING_DIR/provenance.local.sigstore.json")" \
  --arg validation "$(hash_file "$SIGNING_DIR/validation-evidence.json")" \
  --arg validationBundle "$(hash_file "$SIGNING_DIR/validation-evidence.sigstore.json")" \
  '{
    schemaVersion:"1.0",
    issuer:"https://token.actions.githubusercontent.com",
    certificateIdentity:"https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main",
    repository:"satishgampala/devsecops-supply-chain-template",
    workflowName:"Signing",
    workflowRef:"refs/heads/main",
    workflowSHA:$source,
    workflowTrigger:"push",
    cryptographicVerification:true,
    transparencyLogVerified:true,
    embeddedSCTVerified:true,
    artifacts:[
      {role:"local-provenance",path:"provenance.local.json",sha256:$provenance,bundle:"provenance.local.sigstore.json",bundleSHA256:$provenanceBundle,verified:true},
      {role:"oci-archive",path:"image.oci.tar",sha256:$archive,bundle:"image.oci.sigstore.json",bundleSHA256:$archiveBundle,verified:true},
      {role:"spdx-sbom",path:"image.spdx.raw.json",sha256:$sbom,bundle:"image.spdx.sigstore.json",bundleSHA256:$sbomBundle,verified:true},
      {role:"validation-evidence",path:"validation-evidence.json",sha256:$validation,bundle:"validation-evidence.sigstore.json",bundleSHA256:$validationBundle,verified:true}
    ]
  }' >"$SIGNING_DIR/signing-observation.json"

go run ./cmd/signing-policy \
  -policy policy/signing-identity.json \
  -observation "$SIGNING_DIR/signing-observation.json" \
  -expected-sha "$SOURCE_DIGEST" \
  -output "$SIGNING_DIR/signing-decision.json"

FAKE_COSIGN_EXPECTATIONS="$INPUT_DIR/accepted-signatures.json"
jq '.artifacts | map({key:.path,value:.sha256}) | from_entries' \
  "$SIGNING_DIR/signing-decision.json" >"$FAKE_COSIGN_EXPECTATIONS"
export FAKE_COSIGN_EXPECTATIONS

EVIDENCE_DIR="$EVIDENCE_DIR" \
INTEGRITY_DIR="$ROOT/dist" \
SECURITY_DIR="$SECURITY_DIR" \
SIGNING_DIR="$SIGNING_DIR" \
TEST_SUMMARY="$INPUT_DIR/tests.json" \
EVALUATION_TIME="$EVALUATION_TIME" \
SOURCE_DIGEST="$SOURCE_DIGEST" \
  ./scripts/collect-release-evidence.sh

verify_release() {
  output=$1
  shift
  go run ./cmd/releaseverify \
    -policy policy/release-v1.json \
    -evidence-root "${EVIDENCE_DIR#"$ROOT"/}" \
    -manifest release-evidence.json \
    -evaluation-time "$EVALUATION_TIME" \
    -output "$output" \
    "$@"
}

verify_release "$DECISION_DIR/clean.json"

expect_failure() {
  name=$1
  reason=$2
  shift 2
  set +e
  "$@" >/dev/null 2>&1
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf 'fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! jq --exit-status --arg reason "$reason" '.reasonCodes | index($reason) != null' "$DECISION_DIR/$name.json" >/dev/null; then
    printf 'fixture missing reason %s: %s\n' "$reason" "$name" >&2
    exit 1
  fi
}

set +e
FAKE_COSIGN_FAIL=1 verify_release "$DECISION_DIR/signature-invalid.json" >/dev/null 2>&1
signature_status=$?
set -e
if [ "$signature_status" -eq 0 ] || ! jq --exit-status '.reasonCodes | index("SIGNATURE_INVALID") != null' "$DECISION_DIR/signature-invalid.json" >/dev/null; then
  printf '%s\n' 'signature-invalid fixture failed incorrectly' >&2
  exit 1
fi
unset FAKE_COSIGN_FAIL

cp -- "$EVIDENCE_DIR/tests.json" "$EVIDENCE_DIR/tests.json.hold"
cp -- "$EVIDENCE_DIR/release-evidence.json" "$EVIDENCE_DIR/release-evidence.json.hold"
jq '.tests[0].ref = "rewritten after signing"' "$EVIDENCE_DIR/tests.json.hold" >"$EVIDENCE_DIR/tests.json"
jq --arg hash "$(hash_file "$EVIDENCE_DIR/tests.json")" '.tests.sha256 = $hash' \
  "$EVIDENCE_DIR/release-evidence.json.hold" >"$EVIDENCE_DIR/release-evidence.json"
expect_failure rehashed-tests VALIDATION_EVIDENCE_MISMATCH verify_release "$DECISION_DIR/rehashed-tests.json"

# Also rewrite the signed statement and all public hashes. The independently
# frozen signature expectations must still reject the altered statement.
cp -- "$EVIDENCE_DIR/validation-evidence.json" "$EVIDENCE_DIR/validation-evidence.json.hold"
cp -- "$EVIDENCE_DIR/signing-decision.json" "$EVIDENCE_DIR/signing-decision.json.hold"
jq --arg hash "$(hash_file "$EVIDENCE_DIR/tests.json")" '.tests.sha256 = $hash' \
  "$EVIDENCE_DIR/validation-evidence.json.hold" >"$EVIDENCE_DIR/validation-evidence.json"
validation_hash=$(hash_file "$EVIDENCE_DIR/validation-evidence.json")
jq --arg hash "$validation_hash" '(.artifacts[] | select(.role == "validation-evidence")).sha256 = $hash' \
  "$EVIDENCE_DIR/signing-decision.json.hold" >"$EVIDENCE_DIR/signing-decision.json"
jq --arg validation "$validation_hash" --arg signing "$(hash_file "$EVIDENCE_DIR/signing-decision.json")" \
  --arg tests "$(hash_file "$EVIDENCE_DIR/tests.json")" \
  '.validation.sha256 = $validation | .signing.decision.sha256 = $signing | .tests.sha256 = $tests' \
  "$EVIDENCE_DIR/release-evidence.json.hold" >"$EVIDENCE_DIR/release-evidence.json"
expect_failure rewritten-validation SIGNATURE_INVALID verify_release "$DECISION_DIR/rewritten-validation.json"
for name in tests.json release-evidence.json validation-evidence.json signing-decision.json
do
  mv -- "$EVIDENCE_DIR/$name.hold" "$EVIDENCE_DIR/$name"
done

mv "$EVIDENCE_DIR/image.spdx.raw.json" "$EVIDENCE_DIR/image.spdx.raw.json.hold"
expect_failure missing-sbom SBOM_MISSING verify_release "$DECISION_DIR/missing-sbom.json"
mv "$EVIDENCE_DIR/image.spdx.raw.json.hold" "$EVIDENCE_DIR/image.spdx.raw.json"

cp -- "$EVIDENCE_DIR/release-evidence.json" "$EVIDENCE_DIR/release-evidence.json.hold"
jq '.releasePolicySHA256 = "8888888888888888888888888888888888888888888888888888888888888888"' \
  "$EVIDENCE_DIR/release-evidence.json.hold" >"$EVIDENCE_DIR/release-evidence.json"
expect_failure policy-mismatch POLICY_DIGEST_MISMATCH verify_release "$DECISION_DIR/policy-mismatch.json"
mv "$EVIDENCE_DIR/release-evidence.json.hold" "$EVIDENCE_DIR/release-evidence.json"

set +e
go run ./cmd/releaseverify \
  -policy policy/release-v1.json \
  -evidence-root "${EVIDENCE_DIR#"$ROOT"/}" \
  -manifest release-evidence.json \
  -evaluation-time '2026-07-21T12:01:00Z' \
  -output "$DECISION_DIR/time-mismatch.json" >/dev/null 2>&1
time_status=$?
set -e
if [ "$time_status" -eq 0 ] || ! jq --exit-status '.reasonCodes | index("EVALUATION_TIME_MISMATCH") != null' "$DECISION_DIR/time-mismatch.json" >/dev/null; then
  printf '%s\n' 'time-mismatch fixture failed incorrectly' >&2
  exit 1
fi

printf 'release policy fixtures passed; output=%s\n' "$BASE_DIR"
