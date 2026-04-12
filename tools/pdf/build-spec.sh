#!/bin/bash
# Build the Wardline Framework Specification as a PDF.
#
# Pipeline: concatenate chapters → preprocess.py → pandoc (typst output)
# → optional typst compile → PDF.
#
# Requirements: pandoc >= 3.0, typst >= 0.14, mermaid-cli (mmdc), python3.
#
# Usage:
#   ./build-spec.sh              # Generate .typ intermediate only
#   ./build-spec.sh --pdf        # Generate .typ and compile to PDF
#
# Environment:
#   FORCE_DATE   Override the title-page date (default: today).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SPEC_DIR="$PROJECT_ROOT/docs/spec"
OUTPUT_TYP="$SCRIPT_DIR/wardline-specification.typ"
OUTPUT_PDF="$PROJECT_ROOT/docs/assets/wardline-specification.pdf"
MERMAID_DIR="$SCRIPT_DIR/.mermaid-tmp"

CHAPTERS=(
    wardline-01-00-front-matter.md
    wardline-01-01-document-scope.md
    wardline-01-02-what-a-wardline-is.md
    wardline-01-03-the-problem-a-wardline-solves.md
    wardline-01-04-non-goals.md
    wardline-01-05-authority-tier-model.md
    wardline-01-06-authority-tier-enforcement-spec.md
    wardline-01-07-annotation-vocabulary.md
    wardline-01-08-pattern-rules.md
    wardline-01-09-enforcement-layers.md
    wardline-01-10-governance-model.md
    wardline-01-11-verification-properties.md
    wardline-01-12-language-evaluation-criteria.md
    wardline-01-13-residual-risks.md
    wardline-01-14-portability-and-manifest-format.md
    wardline-01-15-conformance.md
    wardline-02-00-front-matter.md
    wardline-02-A-python-binding.md
    wardline-02-B-java-binding.md
)

wl_check_toolchain

COMBINED=$(mktemp)
PROCESSED=$(mktemp)
STAMPED_METADATA=$(mktemp --suffix=.yaml)
trap 'rm -f "$COMBINED" "$PROCESSED" "$STAMPED_METADATA"; rm -rf "$MERMAID_DIR"' EXIT

echo "Concatenating ${#CHAPTERS[@]} spec chapters..."
wl_concat_chapters "$COMBINED" "$SPEC_DIR" "${CHAPTERS[@]}"

echo "Preprocessing markdown..."
python3 "$SCRIPT_DIR/preprocess.py" \
    --profile=spec \
    --input="$COMBINED" \
    --output="$PROCESSED" \
    --mermaid-dir="$MERMAID_DIR" \
    --mermaid-rel-base="$SCRIPT_DIR"

echo "Stamping build date..."
wl_stamp_date "$SCRIPT_DIR/metadata.yaml" "$STAMPED_METADATA"

echo "Generating Typst intermediate..."
wl_run_pandoc "$PROCESSED" "$OUTPUT_TYP" "$STAMPED_METADATA"

echo "Post-processing Typst output..."
python3 "$SCRIPT_DIR/postprocess.py" "$OUTPUT_TYP" "$OUTPUT_TYP"
echo "  -> $OUTPUT_TYP"

if [[ "${1:-}" == "--pdf" ]]; then
    echo "Compiling PDF..."
    wl_compile_pdf "$OUTPUT_TYP" "$OUTPUT_PDF"
    echo "  -> $OUTPUT_PDF"
    echo "  $(wc -c < "$OUTPUT_PDF" | xargs) bytes"
fi

echo "Done."
