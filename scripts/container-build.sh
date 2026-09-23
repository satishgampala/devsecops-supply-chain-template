#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/container-source.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
"$ROOT/scripts/check-toolchain.sh"
"$ROOT/scripts/source-snapshot.sh" "$work/source"
"${DOCKER:-docker}" build --tag "${IMAGE:-devsecops-supply-chain-template:local}" "$work/source"
