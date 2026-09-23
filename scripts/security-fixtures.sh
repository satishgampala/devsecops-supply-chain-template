#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
REPORT_DIR=${FIXTURE_REPORT_DIR:-"$ROOT/.local/security-fixtures/latest"}
CACHE_DIR=${SECURITY_CACHE_DIR:-"$ROOT/.local/security-cache"}

. "$ROOT/scripts/lib/scanner-tools.sh"
VULNERABLE_IMAGE='devsecops-supply-chain-template:vulnerable-fixture'

case "$REPORT_DIR" in
  ''|/) printf '%s\n' 'unsafe fixture report directory' >&2; exit 2 ;;
esac

mkdir -p "$REPORT_DIR" "$CACHE_DIR/trivy"
for scanner in gosec govulncheck gitleaks zizmor osv-scanner trivy-config trivy-license trivy-image
do
  rm -f -- "$REPORT_DIR/$scanner.sarif"
done
uid=$(id -u)
gid=$(id -g)
image_tar="$REPORT_DIR/vulnerable-image.tar"

cleanup() {
  if [ -f "$image_tar" ]; then
    rm -f -- "$image_tar"
  fi
}
trap cleanup EXIT HUP INT TERM

expect_nonzero() {
  name=$1
  shift
  set +e
  "$@"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s unexpectedly passed\n' "$name" >&2
    exit 1
  fi
  printf '%s failed as expected (status=%s)\n' "$name" "$status"
}

cd "$ROOT"

expect_nonzero gosec \
  docker run --rm --user "$uid:$gid" \
    -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomodcache \
    --volume "$ROOT/testdata/security/source:/fixture:ro" \
    --volume "$REPORT_DIR:/reports" --workdir /fixture \
    "$GOSEC_IMAGE" -severity medium -confidence medium \
    -fmt sarif -out /reports/gosec.sarif ./...
test -s "$REPORT_DIR/gosec.sarif"
grep -q '"ruleId": "G302"' "$REPORT_DIR/gosec.sarif"

go -C testdata/security/dependencies mod download
GOTOOLCHAIN="$GO_VERSION" go run "$GOVULNCHECK_REFERENCE" -C testdata/security/dependencies \
  -format sarif ./... >"$REPORT_DIR/govulncheck.sarif"
test -s "$REPORT_DIR/govulncheck.sarif"
grep -q '"ruleId": "GO-2021-0113"' "$REPORT_DIR/govulncheck.sarif"
expect_nonzero govulncheck \
  env GOTOOLCHAIN="$GO_VERSION" go run "$GOVULNCHECK_REFERENCE" -C testdata/security/dependencies ./...

expect_nonzero gitleaks \
  docker run --rm --user "$uid:$gid" \
    --volume "$ROOT/testdata/security/secrets:/fixture:ro" \
    --volume "$REPORT_DIR:/reports" "$GITLEAKS_IMAGE" dir /fixture \
    --config /fixture/gitleaks.toml --redact=100 --no-banner --no-color \
    --report-format sarif --report-path /reports/gitleaks.sarif --exit-code 1
test -s "$REPORT_DIR/gitleaks.sarif"
grep -q '"ruleId": "m02-synthetic-canary"' "$REPORT_DIR/gitleaks.sarif"

docker run --rm --user "$uid:$gid" \
  --volume "$ROOT/testdata/security/workflows:/fixture:ro" "$ZIZMOR_IMAGE" \
  --offline --strict-collection --persona regular --format sarif --no-progress \
  /fixture/untrusted-expression.yml >"$REPORT_DIR/zizmor.sarif"
test -s "$REPORT_DIR/zizmor.sarif"
grep -q '"ruleId": "zizmor/template-injection"' "$REPORT_DIR/zizmor.sarif"
expect_nonzero zizmor \
  docker run --rm --user "$uid:$gid" \
    --volume "$ROOT/testdata/security/workflows:/fixture:ro" "$ZIZMOR_IMAGE" \
    --offline --strict-collection --persona regular --no-progress \
    /fixture/untrusted-expression.yml

expect_nonzero osv-scanner \
  docker run --rm --user "$uid:$gid" \
    --env HOME=/tmp --env GOCACHE=/tmp/go-build \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    --volume "$ROOT/testdata/security/dependencies:/fixture:ro" \
    --volume "$REPORT_DIR:/reports" "$OSV_IMAGE" scan source \
    --format sarif --output-file /reports/osv-scanner.sarif /fixture
test -s "$REPORT_DIR/osv-scanner.sarif"
grep -q '"ruleId": "CVE-2022-32149"' "$REPORT_DIR/osv-scanner.sarif"

expect_nonzero trivy-config \
  docker run --rm --user "$uid:$gid" \
    --volume "$ROOT/testdata/security/iac:/fixture:ro" \
    --volume "$REPORT_DIR:/reports" --volume "$CACHE_DIR/trivy:/cache" \
    "$TRIVY_IMAGE" --cache-dir /cache config \
    --severity MEDIUM,HIGH,CRITICAL --exit-code 1 \
    --format sarif --output /reports/trivy-config.sarif /fixture
test -s "$REPORT_DIR/trivy-config.sarif"
grep -q '"ruleId": "DS-0001"' "$REPORT_DIR/trivy-config.sarif"

expect_nonzero trivy-license \
  docker run --rm --user "$uid:$gid" \
    --volume "$ROOT/testdata/security/licenses:/fixture:ro" \
    --volume "$REPORT_DIR:/reports" --volume "$CACHE_DIR/trivy:/cache" \
    "$TRIVY_IMAGE" --cache-dir /cache fs --scanners license \
    --severity UNKNOWN,MEDIUM,HIGH,CRITICAL --exit-code 1 \
    --format sarif --output /reports/trivy-license.sarif /fixture
test -s "$REPORT_DIR/trivy-license.sarif"
grep -q 'GPL-3.0-only' "$REPORT_DIR/trivy-license.sarif"

docker build --tag "$VULNERABLE_IMAGE" testdata/security/image
docker save --output "$image_tar" "$VULNERABLE_IMAGE"
expect_nonzero trivy-image \
  docker run --rm --user "$uid:$gid" \
    --volume "$REPORT_DIR:/reports" --volume "$CACHE_DIR/trivy:/cache" \
    "$TRIVY_IMAGE" --cache-dir /cache image --input /reports/vulnerable-image.tar \
    --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
    --format sarif --output /reports/trivy-image.sarif
test -s "$REPORT_DIR/trivy-image.sarif"
grep -q '"ruleId":' "$REPORT_DIR/trivy-image.sarif"

printf 'all security fixtures failed as expected; reports: %s\n' "$REPORT_DIR"
