#!/bin/sh

set -eu

ROOT=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
. "$ROOT/scripts/lib/toolchain.sh"

printf '%s\n' "$GO_VERSION" | grep -Eq '^go[0-9]+\.[0-9]+\.[0-9]+$' || {
  printf '%s\n' 'go.mod must contain exactly one stable patch toolchain' >&2
  exit 1
}
[ "$(awk '$1 == "toolchain" {n++} END {print n}' "$ROOT/go.mod")" = 1 ]

expected="docker.io/library/golang:${GO_VERSION#go}-bookworm@sha256:"
builder=$(awk '$1 == "FROM" && $NF == "build" {print $(NF-2)}' "$ROOT/Dockerfile")
case "$builder" in
  "$expected"*) ;;
  *) printf '%s\n' 'Dockerfile builder must match the go.mod toolchain' >&2; exit 1 ;;
esac
printf '%s\n' "${builder#"$expected"}" | grep -Eq '^[a-f0-9]{64}$' || {
  printf '%s\n' 'Dockerfile builder must have a SHA-256 digest pin' >&2
  exit 1
}
jq -e --arg version "$GO_VERSION" '.goVersion == $version' "$ROOT/policy/release-v1.json" >/dev/null || {
  printf '%s\n' 'release policy Go version must match the go.mod toolchain' >&2
  exit 1
}
if grep -Eq '^[[:space:]]+go-version:' "$ROOT"/.github/workflows/*.yml; then
  printf '%s\n' 'setup-go must use go-version-file: go.mod' >&2
  exit 1
fi
printf 'toolchain pins agree: %s\n' "$GO_VERSION"
