#!/bin/sh

set -eu

case "${1:-}" in
  version)
    printf '%s\n' 'GitVersion: v3.1.2'
    exit 0
    ;;
  verify-blob)
    shift
    ;;
  *)
    exit 2
    ;;
esac

if [ "${FAKE_COSIGN_FAIL:-0}" = '1' ]; then
  exit 1
fi

bundle=''
identity=''
issuer=''
workflow=''
repository=''
ref=''
sha=''
trigger=''
artifact=''

while [ "$#" -gt 0 ]
do
  case "$1" in
    --bundle) bundle=$2; shift 2 ;;
    --certificate-identity) identity=$2; shift 2 ;;
    --certificate-oidc-issuer) issuer=$2; shift 2 ;;
    --certificate-github-workflow-name) workflow=$2; shift 2 ;;
    --certificate-github-workflow-repository) repository=$2; shift 2 ;;
    --certificate-github-workflow-ref) ref=$2; shift 2 ;;
    --certificate-github-workflow-sha) sha=$2; shift 2 ;;
    --certificate-github-workflow-trigger) trigger=$2; shift 2 ;;
    --) shift ;;
    --insecure-*) exit 2 ;;
    -*) exit 2 ;;
    *) artifact=$1; shift ;;
  esac
done

for value in "$bundle" "$identity" "$issuer" "$workflow" "$repository" "$ref" "$sha" "$trigger" "$artifact"
do
  [ -n "$value" ] || exit 2
done
[ -f "$bundle" ] || exit 1
[ -f "$artifact" ] || exit 1

# Freeze accepted artifact hashes outside the attacker-controlled evidence tree.
# This models byte binding only; it is not a Sigstore signature implementation.
[ -f "${FAKE_COSIGN_EXPECTATIONS:-}" ] || exit 2
artifact_hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
jq --exit-status --arg name "$(basename "$artifact")" --arg hash "$artifact_hash" \
  '.[$name] == $hash' "$FAKE_COSIGN_EXPECTATIONS" >/dev/null
