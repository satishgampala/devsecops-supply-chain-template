#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
cd "$ROOT"
DOCKER=${DOCKER:-docker}
CURL=${CURL:-curl}
IMAGE=${IMAGE:-devsecops-supply-chain-template:local}
SMOKE_PORT=${SMOKE_PORT:-18080}
DIGEST_RESPONSE='{"algorithm":"sha256","digest":"3f412634a4ea9da04b558d0e32b0062a692e41a1c1d10f0c5c707f14440392ce"}'
SMOKE_EVIDENCE=${SMOKE_EVIDENCE:-"$ROOT/.local/container-smoke.json"}
mkdir -p "$(dirname "$SMOKE_EVIDENCE")"
rm -f -- "$SMOKE_EVIDENCE"
set --
if [ -n "${IMAGE_ARCHIVE:-}" ]; then
  set -- --platform linux/amd64
  IMAGE=$(go run ./cmd/supply-chain subject -artifact "$IMAGE_ARCHIVE")
  "$DOCKER" load --input "$IMAGE_ARCHIVE"
  loaded_image=$("$DOCKER" image inspect --format '{{.Id}}' "$IMAGE")
  [ "$loaded_image" = "$IMAGE" ] || {
    printf '%s\n' 'candidate smoke tests require the containerd image store and digest-addressable OCI images' >&2
    exit 2
  }
fi

container_name="devsecops-supply-chain-template-smoke-$$"
cleanup() {
  "$DOCKER" rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
"$DOCKER" run --detach "$@" \
  --name "$container_name" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 100 \
  --publish "127.0.0.1:$SMOKE_PORT:8080" \
  "$IMAGE" >/dev/null
attempt=0
while :; do
  health="$( "$DOCKER" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container_name" )"
  case "$health" in
    healthy) break ;;
    unhealthy)
      "$DOCKER" logs "$container_name" >&2
      printf '%s\n' 'container became unhealthy' >&2
      exit 1 ;;
  esac
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 40 ]; then
    "$DOCKER" logs "$container_name" >&2
    printf '%s\n' 'container did not become healthy within 40 seconds' >&2
    exit 1
  fi
  sleep 1
done
runtime_user="$( "$DOCKER" inspect --format '{{.Config.User}}' "$container_name" )"
if [ "$runtime_user" != '65532:65532' ]; then
  printf 'unexpected runtime user: %s\n' "$runtime_user" >&2
  exit 1
fi
base_url="http://127.0.0.1:$SMOKE_PORT"
health_response="$( "$CURL" --fail --silent --show-error --max-time 3 "$base_url/healthz" )"
if [ "$health_response" != '{"status":"ok"}' ]; then
  printf 'unexpected health response: %s\n' "$health_response" >&2
  exit 1
fi
digest_response="$( "$CURL" --fail --silent --show-error --max-time 3 \
  --header 'Content-Type: application/json' \
  --data '{"value":"supply-chain"}' \
  "$base_url/v1/digest" )"
if [ "$digest_response" != "$DIGEST_RESPONSE" ]; then
  printf 'unexpected digest response: %s\n' "$digest_response" >&2
  exit 1
fi
if [ -n "${IMAGE_ARCHIVE:-}" ]; then
  runtime_image=$("$DOCKER" inspect --format '{{.Image}}' "$container_name")
  [ "$runtime_image" = "$IMAGE" ] || { printf '%s\n' 'runtime image differs from candidate digest' >&2; exit 1; }
  jq --null-input --arg subject "$runtime_image" \
    '{schemaVersion:"1.0",subjectDigest:$subject,state:"passed"}' >"$SMOKE_EVIDENCE"
fi
printf 'container smoke test passed (user=%s; image=%s)\n' "$runtime_user" "$IMAGE"
