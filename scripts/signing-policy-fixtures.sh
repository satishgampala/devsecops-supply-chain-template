#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${SIGNING_FIXTURE_DIR:-"$ROOT/.local/signing-fixtures"}
POLICY="$ROOT/policy/signing-identity.json"
VALID="$ROOT/testdata/signing/valid-observation.json"
EXPECTED_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

case "$OUTPUT_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'SIGNING_FIXTURE_DIR must remain inside the working tree' >&2; exit 2 ;;
esac

mkdir -p "$OUTPUT_DIR"
for name in valid wrong-identity pull-request wrong-digest unsigned
do
  rm -f -- "$OUTPUT_DIR/$name-observation.json" "$OUTPUT_DIR/$name-decision.json"
done

cd "$ROOT"

go run ./cmd/signing-policy \
  -policy "$POLICY" \
  -observation "$VALID" \
  -expected-sha "$EXPECTED_SHA" \
  -output "$OUTPUT_DIR/valid-decision.json"

expect_failure() {
  name=$1
  reason=$2
  observation="$OUTPUT_DIR/$name-observation.json"
  decision="$OUTPUT_DIR/$name-decision.json"
  set +e
  go run ./cmd/signing-policy \
    -policy "$POLICY" \
    -observation "$observation" \
    -expected-sha "$EXPECTED_SHA" \
    -output "$decision" >/dev/null 2>&1
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf 'fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! jq --exit-status --arg reason "$reason" '.reasonCodes | index($reason) != null' "$decision" >/dev/null; then
    printf 'fixture missing reason %s: %s\n' "$reason" "$name" >&2
    exit 1
  fi
}

jq '.certificateIdentity = "https://github.com/example/other/.github/workflows/signing.yml@refs/heads/main"' \
  "$VALID" >"$OUTPUT_DIR/wrong-identity-observation.json"
expect_failure wrong-identity CERTIFICATE_IDENTITY_MISMATCH

jq '.workflowTrigger = "pull_request"' \
  "$VALID" >"$OUTPUT_DIR/pull-request-observation.json"
expect_failure pull-request WORKFLOW_TRIGGER_DENIED

jq '.artifacts[0].sha256 = "bad"' \
  "$VALID" >"$OUTPUT_DIR/wrong-digest-observation.json"
expect_failure wrong-digest ARTIFACT_DIGEST_INVALID

jq '.cryptographicVerification = false' \
  "$VALID" >"$OUTPUT_DIR/unsigned-observation.json"
expect_failure unsigned CRYPTOGRAPHIC_VERIFICATION_FAILED

printf 'signing policy fixtures passed; output=%s\n' "$OUTPUT_DIR"
