#!/bin/sh

# The caller sets ROOT to the repository root before sourcing this file.
GO_VERSION=$(awk '$1 == "toolchain" {print $2}' "$ROOT/go.mod")
case "$GO_VERSION" in
  go[0-9]*.[0-9]*.[0-9]*) ;;
  *) printf '%s\n' 'go.mod must pin a Go toolchain' >&2; exit 2 ;;
esac
GOTOOLCHAIN=$GO_VERSION
export GO_VERSION GOTOOLCHAIN
