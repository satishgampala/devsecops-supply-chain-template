#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/format-go.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
cd "$ROOT"
git ls-files --cached --others --exclude-standard -z -- '*.go' >"$work/files"
xargs -0 sh -c 'for path do
  if [ -L "$path" ]; then printf "refusing to format symbolic link: %s\n" "$path" >&2; exit 1; fi
  if [ -f "$path" ]; then printf "%s\0" "$path"; fi
done' sh <"$work/files" >"$work/existing"
[ -s "$work/existing" ] || exit 0
case "${1:-check}" in
  write) xargs -0 "${GOFMT:-gofmt}" -w <"$work/existing" ;;
  check)
    xargs -0 "${GOFMT:-gofmt}" -l <"$work/existing" >"$work/unformatted"
    if [ -s "$work/unformatted" ]; then
      printf '%s\n' 'Go files require formatting:' >&2
      cat "$work/unformatted" >&2
      exit 1
    fi
    ;;
  *) printf '%s\n' 'usage: format-go.sh [check|write]' >&2; exit 2 ;;
esac
