#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
REPORT_DIR=${REPORT_DIR:-"$ROOT/.local/security-reports/latest"}
CACHE_DIR=${SECURITY_CACHE_DIR:-"$ROOT/.local/security-cache"}
IMAGE=${IMAGE:-devsecops-supply-chain-template:local}
EVALUATION_TIME=${EVALUATION_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}

case "$REPORT_DIR" in
  /*) ;;
  *) REPORT_DIR="$ROOT/$REPORT_DIR" ;;
esac
case "$CACHE_DIR" in
  /*) ;;
  *) CACHE_DIR="$ROOT/$CACHE_DIR" ;;
esac

GOSEC_IMAGE='ghcr.io/securego/gosec@sha256:4342ad119a7c69f3f4e4ce78d81ba183dc774a70a7a4c6eeb15fe9e511f214f0'
GOVULNCHECK_REFERENCE='golang.org/x/vuln/cmd/govulncheck@v1.6.0'
GITLEAKS_IMAGE='ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
ZIZMOR_IMAGE='ghcr.io/zizmorcore/zizmor@sha256:5800c8d5e83263d68a8874989b0eb3939e177540e9395de48158d24656141ee9'
OSV_IMAGE='ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475'
TRIVY_IMAGE='docker.io/aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f'

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
image_tar="$REPORT_DIR/application-image.tar"
mkdir -p "$ROOT/.local"
# Keep bind-mounted input under the checkout; macOS VM runtimes may not share
# the host's private temporary directory.
source_work=$(mktemp -d "$ROOT/.local/security-source.XXXXXX")
SOURCE_DIR="$source_work/source"

cleanup() {
  rm -rf -- "$source_work"
  if [ -f "$image_tar" ]; then
    rm -f -- "$image_tar"
  fi
}
trap cleanup EXIT HUP INT TERM

"$ROOT/scripts/check-toolchain.sh"
"$ROOT/scripts/source-snapshot.sh" "$SOURCE_DIR"

. "$ROOT/scripts/lib/scanner-runner.sh"

cd "$ROOT"

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

docker build --tag "$IMAGE" "$SOURCE_DIR"
docker save --output "$image_tar" "$IMAGE"

run_file_scan \
  trivy-image "$TRIVY_IMAGE" \
  "$REPORT_DIR/raw/trivy-image.sarif" "$REPORT_DIR/normalized/trivy-image.json" \
  docker run --rm --user "$uid:$gid" \
    --volume "$REPORT_DIR:/reports" --volume "$CACHE_DIR/trivy:/cache" \
    "$TRIVY_IMAGE" --cache-dir /cache image --input /reports/application-image.tar \
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
