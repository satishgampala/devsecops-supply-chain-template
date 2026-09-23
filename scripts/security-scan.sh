#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
REPORT_DIR=${REPORT_DIR:-"$ROOT/.local/security-reports/latest"}
CACHE_DIR=${SECURITY_CACHE_DIR:-"$ROOT/.local/security-cache"}
IMAGE=${IMAGE:-devsecops-supply-chain-template:local}
EVALUATION_TIME=${EVALUATION_TIME:-}
SCANNED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_ARCHIVE=${IMAGE_ARCHIVE:-}
SOURCE_DIGEST=
SUBJECT_DIGEST=

case "$REPORT_DIR" in
  /*) ;;
  *) REPORT_DIR="$ROOT/$REPORT_DIR" ;;
esac
case "$CACHE_DIR" in
  /*) ;;
  *) CACHE_DIR="$ROOT/$CACHE_DIR" ;;
esac

. "$ROOT/scripts/lib/scanner-tools.sh"

case "$REPORT_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'report directory must remain inside the working tree' >&2; exit 2 ;;
esac
case "$CACHE_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'cache directory must remain inside the working tree' >&2; exit 2 ;;
esac

mkdir -p "$REPORT_DIR/raw" "$REPORT_DIR/normalized" "$REPORT_DIR/metadata" "$CACHE_DIR/trivy"

rm -f -- "$REPORT_DIR/decision.json"

uid=$(id -u)
gid=$(id -g)
mkdir -p "$ROOT/.local"
# Keep bind-mounted input under the checkout; macOS VM runtimes may not share
# the host's private temporary directory.
source_work=$(mktemp -d "$ROOT/.local/security-source.XXXXXX")
SOURCE_DIR="$source_work/source"
image_tar="$source_work/candidate.tar"

cleanup() {
  rm -rf -- "$source_work"
}
trap cleanup EXIT HUP INT TERM

"$ROOT/scripts/check-toolchain.sh"
"$ROOT/scripts/source-snapshot.sh" "$SOURCE_DIR"

. "$ROOT/scripts/lib/scanner-runner.sh"

cd "$ROOT"
if [ -n "$IMAGE_ARCHIVE" ]; then
  [ -z "$(git status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' 'candidate scans require a clean working tree' >&2; exit 2;
  }
  SOURCE_DIGEST=$(git rev-parse HEAD)
  cp -- "$IMAGE_ARCHIVE" "$source_work/release.oci.tar"
  SUBJECT_DIGEST=$(go run ./cmd/supply-chain subject -artifact "$source_work/release.oci.tar")
  docker load --input "$source_work/release.oci.tar"
  docker save --output "$image_tar" "$SUBJECT_DIGEST"
  exported_subject=$(go run ./cmd/supply-chain subject -artifact "$image_tar")
  [ "$exported_subject" = "$SUBJECT_DIGEST" ] || {
    printf '%s\n' 'scanner export changed the candidate OCI manifest' >&2; exit 2;
  }
fi

run_gosec() {
  rm -f -- "$REPORT_DIR/raw/gosec.json"
  gosec_status=0
  docker run --rm --user "$uid:$gid" \
    -e GOTOOLCHAIN="$GO_VERSION" -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomodcache \
    --volume "$SOURCE_DIR:/src:ro" --volume "$REPORT_DIR:/reports" --workdir /src \
    "$GOSEC_IMAGE" \
    -track-suppressions -exclude-dir=testdata -severity medium -confidence medium \
    -fmt sarif -out /reports/raw/gosec.sarif -stdout -verbose json ./... >"$REPORT_DIR/raw/gosec.json" || gosec_status=$?
  if ! validate_gosec_report "$REPORT_DIR/raw/gosec.json"; then
    return 2
  fi
  return "$gosec_status"
}

run_file_scan \
  gosec "$GOSEC_IMAGE" \
  "$REPORT_DIR/raw/gosec.sarif" "$REPORT_DIR/normalized/gosec.json" \
  run_gosec

run_stdout_scan \
  govulncheck "$GOVULNCHECK_REFERENCE" \
  "$REPORT_DIR/raw/govulncheck.sarif" "$REPORT_DIR/normalized/govulncheck.json" \
  env GOTOOLCHAIN="$GO_VERSION" go run "$GOVULNCHECK_REFERENCE" -C "$SOURCE_DIR" -format sarif ./...

run_file_scan \
  gitleaks "$GITLEAKS_IMAGE" \
  "$REPORT_DIR/raw/gitleaks.sarif" "$REPORT_DIR/normalized/gitleaks.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$ROOT:/src:ro" --volume "$REPORT_DIR:/reports" \
    "$GITLEAKS_IMAGE" git /src \
    --config /src/.gitleaks.toml --redact=100 --no-banner --no-color \
    --report-format sarif --report-path /reports/raw/gitleaks.sarif --exit-code 10

run_stdout_scan \
  zizmor "$ZIZMOR_IMAGE" \
  "$REPORT_DIR/raw/zizmor.sarif" "$REPORT_DIR/normalized/zizmor.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$SOURCE_DIR:/repo:ro" "$ZIZMOR_IMAGE" \
    --offline --strict-collection --persona regular --format sarif --no-progress /repo

run_file_scan \
  osv-scanner "$OSV_IMAGE" \
  "$REPORT_DIR/raw/osv-scanner.sarif" "$REPORT_DIR/normalized/osv-scanner.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$SOURCE_DIR:/src:ro" --volume "$REPORT_DIR:/reports" \
    "$OSV_IMAGE" scan source --format sarif \
    --output-file /reports/raw/osv-scanner.sarif --allow-no-lockfiles /src

run_file_scan \
  trivy-config "$TRIVY_IMAGE" \
  "$REPORT_DIR/raw/trivy-config.sarif" "$REPORT_DIR/normalized/trivy-config.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$SOURCE_DIR:/src:ro" --volume "$REPORT_DIR:/reports" \
    --volume "$CACHE_DIR/trivy:/cache" "$TRIVY_IMAGE" \
    --cache-dir /cache fs --scanners misconfig \
    --severity MEDIUM,HIGH,CRITICAL --exit-code 10 \
    --skip-dirs /src/testdata/security --skip-dirs /src/.local --skip-dirs /src/.git --skip-dirs /src/dist \
    --format sarif --output /reports/raw/trivy-config.sarif /src

if [ -z "$IMAGE_ARCHIVE" ]; then
  docker build --tag "$IMAGE" "$SOURCE_DIR"
  docker save --output "$image_tar" "$IMAGE"
fi

run_file_scan \
  trivy-image "$TRIVY_IMAGE" \
  "$REPORT_DIR/raw/trivy-image.sarif" "$REPORT_DIR/normalized/trivy-image.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$REPORT_DIR:/reports" --volume "$CACHE_DIR/trivy:/cache" \
    --volume "$image_tar:/candidate.tar:ro" \
    "$TRIVY_IMAGE" --cache-dir /cache image --input /candidate.tar \
    --scanners vuln --severity HIGH,CRITICAL --exit-code 10 \
    --format sarif --output /reports/raw/trivy-image.sarif

run_file_scan \
  trivy-license "$TRIVY_IMAGE" \
  "$REPORT_DIR/raw/trivy-license.sarif" "$REPORT_DIR/normalized/trivy-license.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$SOURCE_DIR:/src:ro" --volume "$REPORT_DIR:/reports" \
    --volume "$CACHE_DIR/trivy:/cache" "$TRIVY_IMAGE" \
    --cache-dir /cache fs --scanners license --license-full \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --exit-code 10 \
    --skip-dirs /src/testdata/security --skip-dirs /src/.local --skip-dirs /src/.git --skip-dirs /src/dist \
    --format sarif --output /reports/raw/trivy-license.sarif /src

docker run --rm "$TRIVY_IMAGE" --version >"$REPORT_DIR/metadata/trivy-version.txt"
GOTOOLCHAIN="$GO_VERSION" go run "$GOVULNCHECK_REFERENCE" -version >"$REPORT_DIR/metadata/govulncheck-version.txt"
if [ -f "$CACHE_DIR/trivy/db/metadata.json" ]; then
  cp "$CACHE_DIR/trivy/db/metadata.json" "$REPORT_DIR/metadata/trivy-db.json"
fi

if [ -n "$IMAGE_ARCHIVE" ]; then
  cmp -- "$IMAGE_ARCHIVE" "$source_work/release.oci.tar" || { printf '%s\n' 'candidate archive changed during scanning' >&2; exit 2; }
fi
EVALUATION_TIME=${EVALUATION_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
set --
for scanner in gitleaks gosec govulncheck osv-scanner trivy-config trivy-image trivy-license zizmor
do
  set -- "$@" -report "$REPORT_DIR/normalized/$scanner.json"
done
go run ./cmd/security-gate \
  -policy policy/security-policy.json \
  -evaluation-time "$EVALUATION_TIME" \
  -output "$REPORT_DIR/decision.json" \
  "$@"

printf 'security scan passed; reports: %s\n' "$REPORT_DIR"
