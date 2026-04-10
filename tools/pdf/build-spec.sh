#!/bin/bash
# Build the Wardline Framework Specification as a PDF.
#
# Pipeline: concatenate spec chapters → pandoc (typst output) → typst compile → PDF
#
# Requirements: pandoc >= 3.0, typst >= 0.14
#
# Usage:
#   ./build-spec.sh              # Generate .typ intermediate only
#   ./build-spec.sh --pdf        # Generate .typ and compile to PDF

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SPEC_DIR="$PROJECT_ROOT/docs/spec"
TEMPLATE="$SCRIPT_DIR/template.typ"
METADATA="$SCRIPT_DIR/metadata.yaml"
OUTPUT_TYP="$SCRIPT_DIR/wardline-specification.typ"
OUTPUT_PDF="$PROJECT_ROOT/docs/assets/wardline-specification.pdf"

# Ordered list of spec chapters
CHAPTERS=(
    wardline-01-00-front-matter.md
    wardline-01-01-what-a-wardline-is.md
    wardline-01-02-the-problem-a-wardline-solves.md
    wardline-01-03-non-goals.md
    wardline-01-04-authority-tier-model.md
    wardline-01-05-authority-tier-enforcement-spec.md
    wardline-01-06-annotation-vocabulary.md
    wardline-01-07-pattern-rules.md
    wardline-01-08-enforcement-layers.md
    wardline-01-09-governance-model.md
    wardline-01-10-verification-properties.md
    wardline-01-11-language-evaluation-criteria.md
    wardline-01-12-residual-risks.md
    wardline-01-13-portability-and-manifest-format.md
    wardline-01-14-conformance.md
    wardline-01-15-document-scope.md
    wardline-02-00-front-matter.md
    wardline-02-A-python-binding.md
    wardline-02-B-java-binding.md
)

# Concatenate chapters into a single markdown file
COMBINED=$(mktemp)
trap 'rm -f "$COMBINED"' EXIT

echo "Concatenating ${#CHAPTERS[@]} spec chapters..."
for chapter in "${CHAPTERS[@]}"; do
    src="$SPEC_DIR/$chapter"
    if [[ ! -f "$src" ]]; then
        echo "  [error] Missing chapter: $chapter" >&2
        exit 1
    fi
    cat "$src" >> "$COMBINED"
    echo -e "\n\n" >> "$COMBINED"
done

# Preprocess: strip metadata lines already handled by the title page
sed -i \
    -e '/^\*\*Date:\*\*/d' \
    -e '/^\*\*Status:\*\*/d' \
    -e '/^\*\*Protective Marking:\*\*/d' \
    -e '/^\*\*Prepared by:\*\*/d' \
    -e '/^\*\*Document type:\*\*/d' \
    -e '/^\*\*Parent paper:\*\*/d' \
    -e '/^\*\*Language bindings:\*\*/d' \
    -e '/^\*\*Classification:\*\*/d' \
    -e '/Digital Transformation Agency/d' \
    "$COMBINED"

# Strip standalone horizontal rules (typst sections provide structure)
sed -i '/^---$/d' "$COMBINED"

# Strip the manual table of contents from the front matter — the typst
# template generates its own via #outline(). The ToC is a list of markdown
# links like [1. What a Wardline is](#1-what-a-wardline-is) between the
# "How to read this document" section and the first numbered section.
python3 -c "
import re, sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
# Remove the Contents heading and the numbered link list that follows
content = re.sub(
    r'## Contents\n.*?(?=# \d+\.|# Part II)',
    '', content, flags=re.DOTALL
)
with open(sys.argv[1], 'w') as f:
    f.write(content)
" "$COMBINED"

# Demote ## to # and ### to ## for proper chapter structure
# The spec uses ## for top-level headings and ### for sections
sed -i 's/^## /# /; s/^### /## /; s/^#### /### /' "$COMBINED"

echo "Generating Typst intermediate..."
pandoc "$COMBINED" \
    --to=typst \
    --template="$TEMPLATE" \
    --metadata-file="$METADATA" \
    --standalone \
    --columns=120 \
    -o "$OUTPUT_TYP"
echo "  -> $OUTPUT_TYP"

# Clean up pandoc table alignment (let template handle it)
sed -i '/^    align: ([^)]*),$/d' "$OUTPUT_TYP"

if [[ "${1:-}" == "--pdf" ]]; then
    echo "Compiling PDF..."
    mkdir -p "$(dirname "$OUTPUT_PDF")"
    cd "$SCRIPT_DIR"
    typst compile --root "$PROJECT_ROOT" "$OUTPUT_TYP" "$OUTPUT_PDF"
    echo "  -> $OUTPUT_PDF"
    echo "  $(wc -c < "$OUTPUT_PDF" | xargs) bytes"
fi

echo "Done."
