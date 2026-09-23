#!/bin/sh

# Sourced by the live runner and isolated execution fixtures.
validate_gosec_report() {
  jq --exit-status '
    has("Golang errors") and
    (.Stats.files | type == "number" and . > 0) and
    (."Golang errors" | (type == "null" or type == "object") and length == 0)
  ' "$1" >/dev/null
}

normalize_failed() {
  scanner=$1
  reference=$2
  output=$3
  diagnostic=$4
  go run ./cmd/sarif-normalizer \
    -scanner "$scanner" \
    -reference "$reference" \
    -state failed \
    -source-digest "${SOURCE_DIGEST:-}" -subject-digest "${SUBJECT_DIGEST:-}" -scanned-at "${SCANNED_AT:-}" \
    -diagnostic "$diagnostic" \
    -output "$output"
}

normalize_completed() {
  scanner=$1
  reference=$2
  input=$3
  output=$4
  scanner_exit=$5
  set --
  if [ "$scanner" = trivy-image ] && [ -f "${CACHE_DIR:-}/trivy/db/metadata.json" ]; then
    database_updated=$(jq -er '.UpdatedAt' "$CACHE_DIR/trivy/db/metadata.json") || return 2
    set -- -database-updated-at "$database_updated"
  fi
  go run ./cmd/sarif-normalizer \
    -scanner "$scanner" \
    -reference "$reference" \
    -input "$input" \
    -scanner-exit-code "$scanner_exit" \
    -source-digest "${SOURCE_DIGEST:-}" -subject-digest "${SUBJECT_DIGEST:-}" -scanned-at "${SCANNED_AT:-}" \
    -output "$output" "$@"
}

finish_scan() {
  scanner=$1
  reference=$2
  raw=$3
  normalized=$4
  status=$5
  if [ -s "$raw" ] && normalize_completed "$scanner" "$reference" "$raw" "$normalized" "$status"; then
    :
  else
    normalize_failed "$scanner" "$reference" "$normalized" "scanner exited with status $status or produced invalid output"
  fi
}

run_file_scan() {
  scanner=$1
  reference=$2
  raw=$3
  normalized=$4
  shift 4
  rm -f -- "$raw" "$normalized"
  set +e
  "$@"
  status=$?
  set -e
  finish_scan "$scanner" "$reference" "$raw" "$normalized" "$status"
}

run_stdout_scan() {
  scanner=$1
  reference=$2
  raw=$3
  normalized=$4
  shift 4
  rm -f -- "$raw" "$normalized"
  set +e
  "$@" >"$raw"
  status=$?
  set -e
  finish_scan "$scanner" "$reference" "$raw" "$normalized" "$status"
}
