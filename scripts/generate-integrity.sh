#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/toolchain.sh"
DIST_DIR=${DIST_DIR:-"$ROOT/dist"}
PLATFORM=${PLATFORM:-linux/amd64}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
SOURCE_URI=${SOURCE_URI:-https://github.com/satishgampala/devsecops-supply-chain-template}
SOURCE_DIGEST=${SOURCE_DIGEST:-$(git -C "$ROOT" rev-parse HEAD)}
SUBJECT_NAME=${SUBJECT_NAME:-ghcr.io/satishgampala/devsecops-supply-chain-template}
BUILD_TYPE=${BUILD_TYPE:-https://github.com/satishgampala/devsecops-supply-chain-template/buildtypes/container/v1}
BUILDER_ID=${BUILDER_ID:-https://github.com/satishgampala/devsecops-supply-chain-template/builders/local-provenance-v1}
INVOCATION_ID=${INVOCATION_ID:-local:$SOURCE_DIGEST}
MODULE_NAME=${MODULE_NAME:-github.com/satishgampala/devsecops-supply-chain-template}

SYFT_IMAGE='docker.io/anchore/syft@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c'

case "$DIST_DIR" in
  "$ROOT"/*) ;;
  *) printf '%s\n' 'DIST_DIR must remain inside the working tree' >&2; exit 2 ;;
esac

if [ "$PLATFORM" != 'linux/amd64' ]; then
  printf '%s\n' 'PLATFORM must be linux/amd64' >&2
  exit 2
fi

if [ "$SOURCE_DATE_EPOCH" != '0' ]; then
  printf '%s\n' 'SOURCE_DATE_EPOCH must be 0' >&2
  exit 2
fi

if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]; then
  printf '%s\n' 'integrity generation requires a clean working tree' >&2
  exit 2
fi

if [ "$SOURCE_DIGEST" != "$(git -C "$ROOT" rev-parse HEAD)" ]; then
  printf '%s\n' 'SOURCE_DIGEST must equal the checked-out commit' >&2
  exit 2
fi
"$ROOT/scripts/check-toolchain.sh"
source_work=$(mktemp -d "${TMPDIR:-/tmp}/integrity-source.XXXXXX")
trap 'rm -rf -- "$source_work"' EXIT HUP INT TERM
mkdir "$source_work/source"
git -C "$ROOT" archive --format=tar --output="$source_work/source.tar" "$SOURCE_DIGEST"
tar -C "$source_work/source" -xf "$source_work/source.tar"

mkdir -p "$DIST_DIR"
for name in \
  image.oci.tar \
  image.spdx.raw.json \
  image.spdx.canonical.json \
  provenance.local.json \
  verification.json \
  tooling.json \
  checksums.sha256
do
  rm -f -- "$DIST_DIR/$name"
done

(
  cd "$source_work/source"
  go build -mod=readonly -o "$source_work/supply-chain" ./cmd/supply-chain
)
# Evidence paths are checked relative to the checkout by the verifier. Build
# the verifier from the same committed snapshot, then execute it at that root.
cd "$ROOT"

docker buildx build \
  --platform "$PLATFORM" \
  --provenance=false \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --output "type=oci,dest=$DIST_DIR/image.oci.tar" \
  "$source_work/source"

uid=$(id -u)
gid=$(id -g)
docker run --rm \
  --user "$uid:$gid" \
  --env HOME=/tmp \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
  --volume "$DIST_DIR:/work" \
  "$SYFT_IMAGE" \
  "oci-archive:/work/image.oci.tar" \
  --output 'spdx-json@2.3=/work/image.spdx.raw.json'

"$source_work/supply-chain" canonicalize \
  -input "$DIST_DIR/image.spdx.raw.json" \
  -output "$DIST_DIR/image.spdx.canonical.json"

"$source_work/supply-chain" provenance \
  -artifact "$DIST_DIR/image.oci.tar" \
  -output "$DIST_DIR/provenance.local.json" \
  -subject-name "$SUBJECT_NAME" \
  -source-uri "$SOURCE_URI" \
  -source-digest "$SOURCE_DIGEST" \
  -build-type "$BUILD_TYPE" \
  -builder-id "$BUILDER_ID" \
  -invocation-id "$INVOCATION_ID" \
  -source-date-epoch "$SOURCE_DATE_EPOCH"

"$source_work/supply-chain" verify \
  -artifact "$DIST_DIR/image.oci.tar" \
  -sbom "$DIST_DIR/image.spdx.raw.json" \
  -provenance "$DIST_DIR/provenance.local.json" \
  -subject-name "$SUBJECT_NAME" \
  -source-uri "$SOURCE_URI" \
  -source-digest "$SOURCE_DIGEST" \
  -build-type "$BUILD_TYPE" \
  -builder-id "$BUILDER_ID" \
  -invocation-id "$INVOCATION_ID" \
  -source-date-epoch "$SOURCE_DATE_EPOCH" \
  -module "$MODULE_NAME" \
  -go-version "$GO_VERSION" \
  -output "$DIST_DIR/verification.json"

printf '%s\n' \
  '{' \
  '  "schemaVersion": "1.0",' \
  '  "platform": "linux/amd64",' \
  '  "sourceDateEpoch": 0,' \
  '  "sbomFormat": "SPDX-2.3",' \
  '  "syft": "docker.io/anchore/syft@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c"' \
  '}' >"$DIST_DIR/tooling.json"

(
  cd "$DIST_DIR"
  shasum -a 256 \
    image.oci.tar \
    image.spdx.raw.json \
    image.spdx.canonical.json \
    provenance.local.json \
    verification.json \
    tooling.json >checksums.sha256
)

subject=$("$source_work/supply-chain" subject -artifact "$DIST_DIR/image.oci.tar")
printf 'integrity evidence verified; subject=%s; output=%s\n' "$subject" "$DIST_DIR"
