#!/bin/sh

set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p .local
WORK=$(mktemp -d "$ROOT/.local/scanner-runner.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM
. "$ROOT/scripts/lib/scanner-runner.sh"

# Reuse the actual execution wrapper, including output deletion and exit handling.
# Keep a space in the filenames to exercise argument boundaries.
raw="$WORK/raw report.sarif"
normalized="$WORK/normalized report.json"
cp testdata/security/sarif/clean.sarif "$raw"
run_file_scan gitleaks fixture "$raw" "$normalized" sh -c 'exit 1'
jq -e '.state == "failed"' "$normalized" >/dev/null
test ! -f "$raw"

run_file_scan gitleaks fixture "$raw" "$normalized" cp testdata/security/sarif/clean.sarif "$raw"
jq -e '.state == "completed" and (.findings | length == 0)' "$normalized" >/dev/null

run_file_scan gitleaks fixture "$raw" "$normalized" sh -c 'cp "$1" "$2"; exit 10' sh testdata/security/sarif/blocking.sarif "$raw"
jq -e '.state == "completed" and (.findings | length == 1)' "$normalized" >/dev/null

run_file_scan gitleaks fixture "$raw" "$normalized" sh -c 'cp "$1" "$2"; exit 1' sh testdata/security/sarif/blocking.sarif "$raw"
jq -e '.state == "failed"' "$normalized" >/dev/null

run_file_scan gitleaks fixture "$raw" "$normalized" cp testdata/security/sarif/malformed.sarif "$raw"
jq -e '.state == "failed"' "$normalized" >/dev/null

run_stdout_scan govulncheck fixture "$raw" "$normalized" sh -c 'exit 1'
jq -e '.state == "failed"' "$normalized" >/dev/null

printf '%s\n' '{"Golang errors":{},"Stats":{"files":1}}' >"$WORK/gosec.json"
validate_gosec_report "$WORK/gosec.json"
for report in \
  '{"Golang errors":{"source.go":[{"error":"processing failed"}]},"Stats":{"files":1}}' \
  '{"Golang errors":{},"Stats":{"files":0}}' \
  '{"Stats":{"files":1}}' \
  '{"Golang errors":"","Stats":{"files":1}}'
do
  printf '%s\n' "$report" >"$WORK/gosec.json"
  if validate_gosec_report "$WORK/gosec.json"; then
    printf '%s\n' 'invalid Gosec processing summary passed' >&2
    exit 1
  fi
done
printf '%s\n' 'scanner execution fixtures passed'
