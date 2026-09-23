#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/format-go.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
cd "$ROOT"
git ls-files --cached --others --exclude-standard -z -- '*.go' >"$work/files"
[ -s "$work/files" ] || exit 0
case "${1:-check}" in
  write) xargs -0 "${GOFMT:-gofmt}" -w <"$work/files" ;;
  check)
    xargs -0 "${GOFMT:-gofmt}" -l <"$work/files" >"$work/unformatted"
    if [ -s "$work/unformatted" ]; then
      printf '%s\n' 'Go files require formatting:' >&2
      cat "$work/unformatted" >&2
      exit 1
    fi
    ;;
  *) printf '%s\n' 'usage: format-go.sh [check|write]' >&2; exit 2 ;;
esac
