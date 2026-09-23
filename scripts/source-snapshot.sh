#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: source-snapshot.sh NEW_DIRECTORY' >&2; exit 2; }
destination=$1
# Require a new destination so a previous scan cannot contribute stale files.
mkdir -- "$destination"
work=$(mktemp -d "${TMPDIR:-/tmp}/source-snapshot.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

# NUL-delimited names preserve spaces and newlines. Keep each operation separate
# so a Git or tar failure cannot be hidden by the final command in a pipeline.
git -C "$ROOT" ls-files --cached --others --exclude-standard -z >"$work/files"
tar -C "$ROOT" --no-recursion --null -T "$work/files" -cf "$work/source.tar"
tar -C "$destination" -xf "$work/source.tar"
if [ -n "$(find "$destination" -type l -print)" ]; then
  printf '%s\n' 'source snapshots do not allow symbolic links' >&2
  exit 1
fi
