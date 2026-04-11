#!/bin/bash
# Build the Wardline Lite practical guide as a PDF.
#
# Uses the same Typst template as the full specification so the Lite
# guide is visually part of the Wardline document family.
#
# Usage:
#   ./build-lite.sh              # Generate .typ intermediate only
#   ./build-lite.sh --pdf        # Generate .typ and compile to PDF
#
# Environment:
#   FORCE_DATE   Override the title-page date (default: today).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SPEC_DIR="$PROJECT_ROOT/docs/spec"
OUTPUT_TYP="$SCRIPT_DIR/wardline-lite.typ"
OUTPUT_PDF="$PROJECT_ROOT/docs/assets/wardline-lite.pdf"
MERMAID_DIR="$SCRIPT_DIR/.mermaid-tmp"

CHAPTERS=(
    wardline-lite.md
)

wl_check_toolchain

COMBINED=$(mktemp)
PROCESSED=$(mktemp)
STAMPED_METADATA=$(mktemp --suffix=.yaml)
trap 'rm -f "$COMBINED" "$PROCESSED" "$STAMPED_METADATA"; rm -rf "$MERMAID_DIR"' EXIT

echo "Concatenating ${#CHAPTERS[@]} Lite chapter(s)..."
wl_concat_chapters "$COMBINED" "$SPEC_DIR" "${CHAPTERS[@]}"

echo "Preprocessing markdown..."
python3 "$SCRIPT_DIR/preprocess.py" \
    --profile=lite \
    --input="$COMBINED" \
    --output="$PROCESSED" \
    --mermaid-dir="$MERMAID_DIR" \
    --mermaid-rel-base="$SCRIPT_DIR"

echo "Stamping build date..."
wl_stamp_date "$SCRIPT_DIR/metadata-lite.yaml" "$STAMPED_METADATA"

echo "Generating Typst intermediate..."
wl_run_pandoc "$PROCESSED" "$OUTPUT_TYP" "$STAMPED_METADATA"
echo "  -> $OUTPUT_TYP"

if [[ "${1:-}" == "--pdf" ]]; then
    echo "Compiling PDF..."
    wl_compile_pdf "$OUTPUT_TYP" "$OUTPUT_PDF"
    echo "  -> $OUTPUT_PDF"
    echo "  $(wc -c < "$OUTPUT_PDF" | xargs) bytes"
fi

echo "Done."
