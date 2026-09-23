#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/maintenance-fixtures.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
fixture="$work/repository with spaces"
mkdir -p "$fixture/scripts/lib" "$fixture/policy" "$fixture/.github/workflows"
cp "$ROOT/scripts/lib/toolchain.sh" "$fixture/scripts/lib/"
cp "$ROOT/scripts/source-snapshot.sh" "$ROOT/scripts/format-go.sh" "$fixture/scripts/"
cp "$ROOT/go.mod" "$ROOT/Dockerfile" "$fixture/"
cp "$ROOT/policy/release-v1.json" "$fixture/policy/"
cp "$ROOT/.github/workflows/ci.yml" "$fixture/.github/workflows/"

expect_failure() {
  if "$@" >"$work/rejected.log" 2>&1; then
    printf 'fixture unexpectedly passed: %s\n' "$*" >&2
    exit 1
  fi
}

"$ROOT/scripts/check-toolchain.sh" "$fixture"
sed 's/-bookworm/-alpine/' "$ROOT/Dockerfile" >"$fixture/Dockerfile"
expect_failure "$ROOT/scripts/check-toolchain.sh" "$fixture"
cp "$ROOT/Dockerfile" "$fixture/Dockerfile"
jq '.goVersion = "go0.0.0"' "$ROOT/policy/release-v1.json" >"$fixture/policy/release-v1.json"
expect_failure "$ROOT/scripts/check-toolchain.sh" "$fixture"
cp "$ROOT/policy/release-v1.json" "$fixture/policy/release-v1.json"
printf '\n          go-version: 0.0.0\n' >>"$fixture/.github/workflows/ci.yml"
expect_failure "$ROOT/scripts/check-toolchain.sh" "$fixture"
cp "$ROOT/.github/workflows/ci.yml" "$fixture/.github/workflows/ci.yml"

git -C "$fixture" init --quiet
printf 'package fixture\n' >"$fixture/tracked.go"
printf 'package fixture\n' >"$fixture/deleted.go"
git -C "$fixture" add go.mod Dockerfile scripts policy .github tracked.go deleted.go
rm -- "$fixture/deleted.go"
printf 'package changed\n' >"$fixture/tracked.go"
printf 'package fixture\n' >"$fixture/new file.go"
printf '/ignored/\n' >"$fixture/.gitignore"
printf '/nested-worktree/\n' >"$fixture/.git/info/exclude"
mkdir -p "$fixture/ignored" "$fixture/nested-worktree"
printf 'this is not Go\n' >"$fixture/ignored/broken.go"
printf 'this is not Go\n' >"$fixture/nested-worktree/broken.go"
"$fixture/scripts/source-snapshot.sh" "$work/snapshot"
cmp "$fixture/tracked.go" "$work/snapshot/tracked.go"
cmp "$fixture/new file.go" "$work/snapshot/new file.go"
[ ! -e "$work/snapshot/.git" ]
[ ! -e "$work/snapshot/deleted.go" ]
[ ! -e "$work/snapshot/ignored" ]
[ ! -e "$work/snapshot/nested-worktree" ]
expect_failure "$fixture/scripts/source-snapshot.sh" "$work/snapshot"
"$fixture/scripts/format-go.sh" check
printf 'package fixture; func example(){}\n' >"$fixture/new file.go"
expect_failure "$fixture/scripts/format-go.sh" check
"$fixture/scripts/format-go.sh" write
"$fixture/scripts/format-go.sh" check
ln -s "$work" "$fixture/external-link"
expect_failure "$fixture/scripts/source-snapshot.sh" "$work/linked-snapshot"
ln -s "$fixture/tracked.go" "$fixture/linked.go"
expect_failure "$fixture/scripts/format-go.sh" write
printf '%s\n' 'maintenance fixtures passed: version drift, source isolation, formatting scope, and symlink rejection'
