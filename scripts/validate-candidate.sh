#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
DIST_DIR=${DIST_DIR:-"$ROOT/dist"}
case "$DIST_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'DIST_DIR must remain inside the working tree' >&2; exit 2 ;;
esac
cd "$ROOT"
[ -z "$(git status --porcelain --untracked-files=all)" ] || {
  printf '%s\n' 'candidate validation requires a clean working tree' >&2
  exit 2
}
source_digest=$(git rev-parse HEAD)
mkdir -p "$DIST_DIR"
rm -f -- "$DIST_DIR/tests.json" "$DIST_DIR/container-smoke.json"

make verify
make security-fixtures
DIST_DIR="$DIST_DIR" make integrity
archive_hash=$(shasum -a 256 "$DIST_DIR/image.oci.tar" | awk '{print $1}')
IMAGE_ARCHIVE="$DIST_DIR/image.oci.tar" SMOKE_EVIDENCE="$DIST_DIR/container-smoke.json" make container-smoke
IMAGE_ARCHIVE="$DIST_DIR/image.oci.tar" REPORT_DIR="$DIST_DIR/security" make security-scan

[ "$archive_hash" = "$(shasum -a 256 "$DIST_DIR/image.oci.tar" | awk '{print $1}')" ] || {
  printf '%s\n' 'candidate archive changed during validation' >&2
  exit 1
}
[ "$source_digest" = "$(git rev-parse HEAD)" ] && [ -z "$(git status --porcelain --untracked-files=all)" ] || {
  printf '%s\n' 'source changed during validation' >&2
  exit 1
}
# The subject comes from the running container's observed image identity.
subject=$(jq -er 'select(.state == "passed") | .subjectDigest' "$DIST_DIR/container-smoke.json")
[ "$subject" = "$(go run ./cmd/supply-chain subject -artifact "$DIST_DIR/image.oci.tar")" ]
jq --null-input --arg source "$source_digest" --arg subject "$subject" \
  '{schemaVersion:"1.0",sourceDigest:$source,subjectDigest:$subject,tests:[
    {id:"build",state:"passed",ref:"make build"},
    {id:"container-smoke",state:"passed",ref:"make container-smoke IMAGE_ARCHIVE=dist/image.oci.tar"},
    {id:"host",state:"passed",ref:"make verify"},
    {id:"integrity",state:"passed",ref:"make integrity"},
    {id:"race",state:"passed",ref:"make test-race"},
    {id:"security-fixtures",state:"passed",ref:"make security-fixtures"}
  ]}' >"$DIST_DIR/tests.json"
printf 'candidate validated; source=%s; subject=%s; output=%s\n' "$source_digest" "$subject" "$DIST_DIR"
