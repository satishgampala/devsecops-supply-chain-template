#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
OLD_REPOSITORY='satishgampala/devsecops-supply-chain-template'
OLD_MODULE='github.com/satishgampala/devsecops-supply-chain-template'
OLD_ARTIFACT='ghcr.io/satishgampala/devsecops-supply-chain-template'
OLD_SOURCE_URI='https://github.com/satishgampala/devsecops-supply-chain-template'
OLD_CERTIFICATE_IDENTITY='https://github.com/satishgampala/devsecops-supply-chain-template/.github/workflows/signing.yml@refs/heads/main'
OLD_SERVICE='devsecops-supply-chain-template'
OLD_CODEOWNER='@satishgampala'

usage() {
  printf '%s\n' \
    'usage: scripts/initialize-template.sh \\' \
    '  --repository OWNER/REPOSITORY \\' \
    '  --module MODULE_PATH \\' \
    '  --artifact ghcr.io/OWNER/NAME \\' \
    '  --service-name DNS_LABEL \\' \
    '  --codeowner @USER_OR_ORG/TEAM' >&2
  exit 2
}

repository=
module=
artifact=
service_name=
codeowner=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      [ "$#" -ge 2 ] || usage
      repository=$2
      shift 2
      ;;
    --module)
      [ "$#" -ge 2 ] || usage
      module=$2
      shift 2
      ;;
    --artifact)
      [ "$#" -ge 2 ] || usage
      artifact=$2
      shift 2
      ;;
    --service-name)
      [ "$#" -ge 2 ] || usage
      service_name=$2
      shift 2
      ;;
    --codeowner)
      [ "$#" -ge 2 ] || usage
      codeowner=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$repository" ] || usage
[ -n "$module" ] || usage
[ -n "$artifact" ] || usage
[ -n "$service_name" ] || usage
[ -n "$codeowner" ] || usage

printf '%s' "$repository" |
  grep --extended-regexp --quiet '^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$' ||
  { printf '%s\n' 'repository must be OWNER/REPOSITORY' >&2; exit 2; }
printf '%s' "$module" |
  grep --extended-regexp --quiet '^[A-Za-z0-9][A-Za-z0-9.-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)+$' ||
  { printf '%s\n' 'module must be a slash-delimited Go module path' >&2; exit 2; }
printf '%s' "$artifact" |
  grep --extended-regexp --quiet '^ghcr\.io/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)+$' ||
  { printf '%s\n' 'artifact must be a lowercase ghcr.io repository path' >&2; exit 2; }
printf '%s' "$service_name" |
  grep --extended-regexp --quiet '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' ||
  { printf '%s\n' 'service-name must be a lowercase DNS label of at most 63 characters' >&2; exit 2; }
printf '%s' "$codeowner" |
  grep --extended-regexp --quiet '^@[A-Za-z0-9][A-Za-z0-9-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)?$' ||
  { printf '%s\n' 'codeowner must be @USER or @ORG/TEAM' >&2; exit 2; }

case "/$repository/$module/$artifact/" in
  *'/../'*|*'/./'*) printf '%s\n' 'identity path segments must not be dot segments' >&2; exit 2 ;;
esac

[ "$repository" != "$OLD_REPOSITORY" ] ||
  { printf '%s\n' 'repository identity is already the template default' >&2; exit 2; }
[ "$module" != "$OLD_MODULE" ] ||
  { printf '%s\n' 'module identity is already the template default' >&2; exit 2; }
[ "$artifact" != "$OLD_ARTIFACT" ] ||
  { printf '%s\n' 'artifact identity is already the template default' >&2; exit 2; }
[ "$service_name" != "$OLD_SERVICE" ] ||
  { printf '%s\n' 'service identity is already the template default' >&2; exit 2; }
[ "$codeowner" != "$OLD_CODEOWNER" ] ||
  { printf '%s\n' 'codeowner is already the template default' >&2; exit 2; }

command -v git >/dev/null 2>&1 || { printf '%s\n' 'git is required' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'jq is required' >&2; exit 2; }
command -v perl >/dev/null 2>&1 || { printf '%s\n' 'perl is required' >&2; exit 2; }
command -v shasum >/dev/null 2>&1 || { printf '%s\n' 'shasum is required' >&2; exit 2; }

repository_root=$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null) ||
  { printf '%s\n' 'template initialization requires a Git repository' >&2; exit 2; }
[ "$repository_root" = "$ROOT" ] ||
  { printf '%s\n' 'initializer must run from its repository root' >&2; exit 2; }
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ] ||
  { printf '%s\n' 'template initialization requires a clean working tree' >&2; exit 2; }

[ "$(sed -n '1p' "$ROOT/go.mod")" = "module $OLD_MODULE" ] ||
  { printf '%s\n' 'go.mod does not contain the uninitialized template module' >&2; exit 2; }
[ "$(jq -r '.repository' "$ROOT/policy/signing-identity.json")" = "$OLD_REPOSITORY" ] ||
  { printf '%s\n' 'signing policy is not in the uninitialized template state' >&2; exit 2; }
[ "$(jq -r '.artifactName' "$ROOT/policy/release-v1.json")" = "$OLD_ARTIFACT" ] ||
  { printf '%s\n' 'release policy is not in the uninitialized template state' >&2; exit 2; }

replace_exact() {
  old_value=$1
  new_value=$2
  matches=$(git -C "$ROOT" grep -Il --fixed-strings "$old_value" 2>/dev/null || true)
  [ -n "$matches" ] || return 0
  printf '%s\n' "$matches" |
    while IFS= read -r relative_path; do
      case "$relative_path" in
        scripts/initialize-template.sh|docs/guides/adoption.md|docs/roadmap/evidence/*|docs/roadmap/implementation-plans/*)
          continue
          ;;
      esac
      OLD_VALUE=$old_value NEW_VALUE=$new_value \
        perl -0pi -e 's/\Q$ENV{OLD_VALUE}\E/$ENV{NEW_VALUE}/g' -- "$ROOT/$relative_path"
    done
}

new_source_uri="https://github.com/$repository"
new_certificate_identity="$new_source_uri/.github/workflows/signing.yml@refs/heads/main"

replace_exact "$OLD_CERTIFICATE_IDENTITY" "$new_certificate_identity"
replace_exact "$OLD_SOURCE_URI" "$new_source_uri"
replace_exact "$OLD_ARTIFACT" "$artifact"
replace_exact "$OLD_MODULE" "$module"
replace_exact "$OLD_REPOSITORY" "$repository"
replace_exact "$OLD_SERVICE:local" "$service_name:local"
replace_exact "$OLD_SERVICE-smoke-" "$service_name-smoke-"
replace_exact "$OLD_SERVICE:vulnerable-fixture" "$service_name:vulnerable-fixture"
replace_exact "$OLD_CODEOWNER" "$codeowner"

security_policy_sha=$(shasum -a 256 "$ROOT/policy/security-policy.json" | awk '{print $1}')
signing_policy_sha=$(shasum -a 256 "$ROOT/policy/signing-identity.json" | awk '{print $1}')
release_policy_tmp=$(mktemp "$ROOT/policy/release-v1.json.XXXXXX")
trap 'rm -f -- "$release_policy_tmp"' EXIT HUP INT TERM
jq \
  --arg security "$security_policy_sha" \
  --arg signing "$signing_policy_sha" \
  '.securityPolicySHA256 = $security | .signingPolicySHA256 = $signing' \
  "$ROOT/policy/release-v1.json" >"$release_policy_tmp"
chmod 0644 "$release_policy_tmp"
mv -- "$release_policy_tmp" "$ROOT/policy/release-v1.json"
trap - EXIT HUP INT TERM

jq --exit-status --arg expected "$repository" '.repository == $expected' \
  "$ROOT/policy/signing-identity.json" >/dev/null
jq --exit-status --arg expected "$artifact" '.artifactName == $expected' \
  "$ROOT/policy/release-v1.json" >/dev/null
jq --exit-status --arg expected "$module" '.module == $expected' \
  "$ROOT/policy/release-v1.json" >/dev/null
jq --exit-status --arg expected "$signing_policy_sha" '.signingPolicySHA256 == $expected' \
  "$ROOT/policy/release-v1.json" >/dev/null

remaining=$(
  git -C "$ROOT" grep -n --fixed-strings "$OLD_REPOSITORY" -- \
    '*.go' go.mod Makefile 'policy/*.json' 'scripts/*.sh' \
    '.github/workflows/*.yml' 'testdata/*.json' 'testdata/**/*.json' 2>/dev/null |
    grep -v '^scripts/initialize-template.sh:' || true
)
[ -z "$remaining" ] || {
  printf '%s\n' 'template repository identity remains in an executable path:' "$remaining" >&2
  exit 1
}

printf 'template initialized; repository=%s; module=%s; artifact=%s; service=%s; codeowner=%s\n' \
  "$repository" "$module" "$artifact" "$service_name" "$codeowner"
printf '%s\n' 'review and commit the identity diff, then run the adoption-guide verification commands'
