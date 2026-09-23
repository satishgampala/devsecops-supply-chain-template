#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
DOCKER=${DOCKER:-docker}
LYCHEE='docker.io/lycheeverse/lychee:0.24.2@sha256:e2d19e57cf6ab037026f20b8e449a1f30d9d7f81eef4194763aab2eab20bd28d'
MERMAID='ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.12.0@sha256:bad64c9d9ad917c8dfbe9d9e9c162b96f6615ff019b37058638d16eb27ce7783'
mkdir -p "$ROOT/.local"
work_dir=$(mktemp -d "$ROOT/.local/docs-check.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
"$ROOT/scripts/source-snapshot.sh" "$work_dir/source"
mkdir "$work_dir/rendered"

"$DOCKER" run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 100 \
  --user "$(id -u):$(id -g)" --tmpfs /tmp \
  --mount "type=bind,src=$work_dir/source,dst=/input,readonly" --workdir /input \
  "$LYCHEE" --offline --include-fragments --root-dir /input \
  '*.md' 'docs/**/*.md'

# Mermaid CLI extracts fenced diagrams directly from Markdown. Keep source
# read-only and render each document into its own directory to avoid collisions.
find "$work_dir/source" -name '*.md' -type f -exec sh -eu -c '
  source_dir=$1; output_dir=$2; image=$3; docker=$4; shift 4
  for path do
    if grep -q "^\`\`\`mermaid" "$path"; then
      relative=${path#"$source_dir/"}
      mkdir -p "$output_dir/$relative"
      "$docker" run --rm --network none --cap-drop ALL \
        --security-opt no-new-privileges:true --pids-limit 256 \
        --user "$(id -u):$(id -g)" \
        --mount "type=bind,src=$source_dir,dst=/input,readonly" \
        --mount "type=bind,src=$output_dir,dst=/output" \
        "$image" -i "/input/$relative" -o "/output/$relative/rendered.md"
    fi
  done
' sh "$work_dir/source" "$work_dir/rendered" "$MERMAID" "$DOCKER" {} +
printf '%s\n' 'local Markdown links, fragments, and Mermaid diagrams passed'
