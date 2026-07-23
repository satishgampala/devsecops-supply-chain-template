#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-template-fixture.XXXXXX")
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd -P)
SOURCE_LIST="$WORK_DIR/tracked-files.txt"
FIXTURE="$WORK_DIR/consumer"

git -C "$ROOT" ls-files >"$SOURCE_LIST"
mkdir -p "$FIXTURE"
(
  cd "$ROOT"
  tar -cf - -T "$SOURCE_LIST"
) | (
  cd "$FIXTURE"
  tar -xf -
)

git -C "$FIXTURE" init --quiet
git -C "$FIXTURE" config user.name 'Template Fixture'
git -C "$FIXTURE" config user.email 'template-fixture@example.invalid'
git -C "$FIXTURE" add --all
git -C "$FIXTURE" commit --quiet -m 'seed template fixture'

if "$FIXTURE/scripts/initialize-template.sh" \
  --repository '../invalid' \
  --module 'github.com/example-org/secure-service' \
  --artifact 'ghcr.io/example-org/secure-service' \
  --service-name 'secure-service'
then
  printf '%s\n' 'invalid repository fixture unexpectedly succeeded' >&2
  exit 1
fi
[ -z "$(git -C "$FIXTURE" status --porcelain --untracked-files=all)" ]

"$FIXTURE/scripts/initialize-template.sh" \
  --repository 'example-org/secure-service' \
  --module 'github.com/example-org/secure-service' \
  --artifact 'ghcr.io/example-org/secure-service' \
  --service-name 'secure-service'

[ "$(sed -n '1p' "$FIXTURE/go.mod")" = 'module github.com/example-org/secure-service' ]
[ "$(jq -r '.repository' "$FIXTURE/policy/signing-identity.json")" = 'example-org/secure-service' ]
[ "$(jq -r '.artifactName' "$FIXTURE/policy/release-v1.json")" = 'ghcr.io/example-org/secure-service' ]
[ "$(jq -r '.module' "$FIXTURE/policy/release-v1.json")" = 'github.com/example-org/secure-service' ]

signing_sha=$(shasum -a 256 "$FIXTURE/policy/signing-identity.json" | awk '{print $1}')
[ "$(jq -r '.signingPolicySHA256' "$FIXTURE/policy/release-v1.json")" = "$signing_sha" ]

remaining=$(
  git -C "$FIXTURE" grep -n --fixed-strings 'satishgampala/devsecops-supply-chain-template' -- \
    '*.go' go.mod Makefile 'policy/*.json' 'scripts/*.sh' \
    '.github/workflows/*.yml' 'testdata/*.json' 'testdata/**/*.json' 2>/dev/null |
    grep -v '^scripts/initialize-template.sh:' || true
)
[ -z "$remaining" ] || {
  printf '%s\n' 'old executable identity remains after initialization:' "$remaining" >&2
  exit 1
}

git -C "$FIXTURE" add --all
git -C "$FIXTURE" commit --quiet -m 'initialize secure service'

make -C "$FIXTURE" verify
make -C "$FIXTURE" signing-test
make -C "$FIXTURE" release-policy-test

printf '\nfunc broken(' >>"$FIXTURE/cmd/service/main.go"
if make -C "$FIXTURE" verify >/dev/null 2>&1; then
  printf '%s\n' 'seeded source defect unexpectedly passed verification' >&2
  exit 1
fi

printf 'template fixtures passed; initialized repository=%s\n' "$FIXTURE"
