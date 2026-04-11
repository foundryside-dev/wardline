#!/bin/bash
# Deploy built PDFs to the wardline.dev web root.
#
# Usage:
#   ./deploy.sh              # Copy both PDFs into place
#   ./deploy.sh --dry-run    # Show what would be copied without touching files
#   ./deploy.sh <name>...    # Deploy a subset (e.g. `wardline-lite`)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$PROJECT_ROOT/docs/assets"
DST_DIR="/var/www/wardline.dev/assets"

ALL_PDFS=(
    wardline-specification
    wardline-lite
)

dry_run=0
selected=()
for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=1 ;;
        -*) echo "[error] unknown flag: $arg" >&2; exit 2 ;;
        *)  selected+=("$arg") ;;
    esac
done

if [[ ${#selected[@]} -eq 0 ]]; then
    selected=("${ALL_PDFS[@]}")
fi

if [[ ! -d "$DST_DIR" ]]; then
    echo "[error] destination missing: $DST_DIR" >&2
    exit 1
fi

status=0
for name in "${selected[@]}"; do
    src="$SRC_DIR/$name.pdf"
    dst="$DST_DIR/$name.pdf"
    if [[ ! -f "$src" ]]; then
        echo "[error] source missing: $src (build the PDF first)" >&2
        status=1
        continue
    fi
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        echo "  unchanged: $name.pdf"
        continue
    fi
    if (( dry_run )); then
        printf '  [dry-run] %s -> %s (%s bytes)\n' "$src" "$dst" "$(wc -c < "$src")"
    else
        cp -v "$src" "$dst"
    fi
done

exit "$status"
