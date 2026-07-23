#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE_DIR=${REPRO_DIR:-"$ROOT/.local/integrity-repro"}

case "$BASE_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'REPRO_DIR must remain inside the working tree' >&2; exit 2 ;;
esac

for run in first second
do
  directory="$BASE_DIR/$run"
  mkdir -p "$directory"
  DIST_DIR="$directory" "$ROOT/scripts/generate-integrity.sh"
done

for name in image.oci.tar image.spdx.canonical.json provenance.local.json tooling.json
do
  if ! cmp -s "$BASE_DIR/first/$name" "$BASE_DIR/second/$name"; then
    printf 'reproducibility mismatch: %s\n' "$name" >&2
    exit 1
  fi
done

first_subject=$(cd "$ROOT" && go run ./cmd/supply-chain subject -artifact "$BASE_DIR/first/image.oci.tar")
second_subject=$(cd "$ROOT" && go run ./cmd/supply-chain subject -artifact "$BASE_DIR/second/image.oci.tar")
if [ "$first_subject" != "$second_subject" ]; then
  printf '%s\n' 'reproducibility mismatch: OCI manifest subject' >&2
  exit 1
fi

printf 'reproducibility verified; subject=%s; output=%s\n' "$first_subject" "$BASE_DIR"
