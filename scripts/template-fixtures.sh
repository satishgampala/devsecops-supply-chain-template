#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
# Initialization remains one-time. In an adopted repository, exercise its
# current policy contracts rather than attempting to initialize it again.
template_module=$(sed -n "s/^OLD_MODULE='\(.*\)'$/\1/p" "$ROOT/scripts/initialize-template.sh")
if [ "$(sed -n 's/^module //p' "$ROOT/go.mod")" != "$template_module" ]; then
  make -C "$ROOT" signing-test release-policy-test
  printf '%s\n' 'initialized repository policy contracts passed'
  exit 0
fi

mkdir -p "$ROOT/.local"
WORK_DIR=$(mktemp -d "$ROOT/.local/template-fixtures.XXXXXX")
for owner in example-org ExampleOrg
do
  FIXTURE="$WORK_DIR/$owner"
  repository="$owner/secure-service"
  [ "$owner" != ExampleOrg ] || repository="$owner/Secure-Service"
  module="github.com/$repository"
  "$ROOT/scripts/source-snapshot.sh" "$FIXTURE"

  git -C "$FIXTURE" init --quiet
  git -C "$FIXTURE" config user.name 'Template Fixture'
  git -C "$FIXTURE" config user.email 'template-fixture@example.invalid'
  git -C "$FIXTURE" ls-files --cached --others --exclude-standard -z |
    git -C "$FIXTURE" --literal-pathspecs add --pathspec-from-file=- --pathspec-file-nul
  git -C "$FIXTURE" commit --quiet -m 'seed template fixture'

  if "$FIXTURE/scripts/initialize-template.sh" \
    --repository '../invalid' \
    --module "$module" \
    --artifact 'ghcr.io/example-org/secure-service' \
    --service-name 'secure-service' \
    --codeowner '@example-org/security'
  then
    printf '%s\n' 'invalid repository fixture unexpectedly succeeded' >&2
    exit 1
  fi
  [ -z "$(git -C "$FIXTURE" status --porcelain --untracked-files=all)" ]

  "$FIXTURE/scripts/initialize-template.sh" \
    --repository "$repository" \
    --module "$module" \
    --artifact 'ghcr.io/example-org/secure-service' \
    --service-name 'secure-service' \
    --codeowner '@example-org/security'

  [ "$(sed -n '1p' "$FIXTURE/go.mod")" = "module $module" ]
  [ "$(jq -r '.repository' "$FIXTURE/policy/signing-identity.json")" = "$repository" ]
  [ "$(jq -r '.artifactName' "$FIXTURE/policy/release-v1.json")" = 'ghcr.io/example-org/secure-service' ]
  [ "$(jq -r '.module' "$FIXTURE/policy/release-v1.json")" = "$module" ]
  grep --fixed-strings --quiet '@example-org/security' "$FIXTURE/.github/CODEOWNERS"

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

  git -C "$FIXTURE" ls-files --cached --others --exclude-standard -z |
    git -C "$FIXTURE" --literal-pathspecs add --pathspec-from-file=- --pathspec-file-nul
  git -C "$FIXTURE" commit --quiet -m 'initialize secure service'

  make -C "$FIXTURE" verify
  make -C "$FIXTURE" template-test

  printf '\nfunc broken(' >>"$FIXTURE/cmd/service/main.go"
  if make -C "$FIXTURE" verify >/dev/null 2>&1; then
    printf '%s\n' 'seeded source defect unexpectedly passed verification' >&2
    exit 1
  fi

  printf 'template fixtures passed; initialized repository=%s\n' "$FIXTURE"
done
