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
LUA_FILTER="$SCRIPT_DIR/fix-tables.lua"
OUTPUT_TYP="$SCRIPT_DIR/wardline-specification.typ"
OUTPUT_PDF="$PROJECT_ROOT/docs/assets/wardline-specification.pdf"

# Version checks — fail fast if toolchain is outside tested bounds
PANDOC_VER="$(pandoc --version | head -1 | grep -oP '[\d.]+')"
TYPST_VER="$(typst --version 2>/dev/null | grep -oP '[\d.]+' || echo "0")"
if ! printf '%s\n' "3.0" "$PANDOC_VER" | sort -V | head -1 | grep -q "3.0"; then
    echo "[error] pandoc >= 3.0 required (found $PANDOC_VER)" >&2; exit 1
fi

# Ordered list of spec chapters
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
    r'### Contents\n.*?(?=### \d+\.|## Part II)',
    '', content, flags=re.DOTALL
)
with open(sys.argv[1], 'w') as f:
    f.write(content)
" "$COMBINED"

# Convert mkdocs admonitions (!!! type "title") to blockquotes
python3 -c "
import re, sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
def convert_admonition(m):
    atype = m.group(1)
    title = m.group(2) or atype.capitalize()
    body = m.group(3)
    # Remove the 4-space indent from the body
    lines = []
    for line in body.split('\n'):
        if line.startswith('    '):
            lines.append('> ' + line[4:])
        elif line.strip() == '':
            lines.append('>')
        else:
            lines.append('> ' + line)
    body_text = '\n'.join(lines).lstrip('> ')
    return '> **' + title + '.**\n>\n> ' + body_text
content = re.sub(
    r'^!!! +(\w+) *(?:\"([^\"]*)\")?\n((?:    .*\n|\n)*)',
    convert_admonition, content, flags=re.MULTILINE
)
with open(sys.argv[1], 'w') as f:
    f.write(content)
" "$COMBINED"

# Flip horizontal mermaid diagrams to vertical for PDF (LR → TB)
sed -i 's/^graph LR$/graph TB/' "$COMBINED"

# Render mermaid code blocks to PNG images
MERMAID_DIR="$SCRIPT_DIR/.mermaid-tmp"
mkdir -p "$MERMAID_DIR"
python3 -c "
import re, sys, subprocess, os
mdir = sys.argv[2]
with open(sys.argv[1], 'r') as f:
    content = f.read()
counter = 0
def render_mermaid(m):
    global counter
    counter += 1
    code = m.group(1)
    mmd_file = os.path.join(mdir, f'diagram-{counter}.mmd')
    png_file = os.path.join(mdir, f'diagram-{counter}.png')
    with open(mmd_file, 'w') as f:
        f.write(code)
    result = subprocess.run(['mmdc', '-i', mmd_file, '-o', png_file, '-b', 'white', '-t', 'neutral', '-s', '3'],
                   capture_output=True, timeout=30)
    if os.path.exists(png_file):
        print(f'  Rendered diagram-{counter}.png', file=sys.stderr)
        rel_path = os.path.relpath(png_file, sys.argv[3])
        return f'![]({rel_path})'
    print(f'  Failed diagram-{counter}: {result.stderr.decode()}', file=sys.stderr)
    return m.group(0)
content = re.sub(r'\x60\x60\x60mermaid\n(.*?)\x60\x60\x60', render_mermaid, content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
" "$COMBINED" "$MERMAID_DIR" "$SCRIPT_DIR"

# Strip document-level headings — the title page handles these
sed -i '/^## Wardline Framework Specification$/d' "$COMBINED"
sed -i '/^### Semantic Boundary Classification and Enforcement$/d' "$COMBINED"

# Convert Part II title to a chapter-level heading
sed -i 's/^## Part II/# Part II/' "$COMBINED"

# Promote headings by removing two leading # characters:
# ### → #, #### → ##, ##### → ###, ###### → ####
# Uses python to avoid sed's sequential-substitution pitfall.
python3 -c "
import re, sys
with open(sys.argv[1], 'r') as f:
    lines = f.readlines()
out = []
for line in lines:
    m = re.match(r'^(#{3,})\s', line)
    if m:
        old_level = len(m.group(1))
        new_hashes = '#' * (old_level - 2)
        line = new_hashes + line[old_level:]
    out.append(line)
with open(sys.argv[1], 'w') as f:
    f.writelines(out)
" "$COMBINED"

echo "Generating Typst intermediate..."
pandoc "$COMBINED" \
    --to=typst \
    --template="$TEMPLATE" \
    --metadata-file="$METADATA" \
    --lua-filter="$LUA_FILTER" \
    --standalone \
    --columns=120 \
    -o "$OUTPUT_TYP"
echo "  -> $OUTPUT_TYP"

# Clean up pandoc table alignment (let template handle it)
sed -i '/^    align: ([^)]*),$/d' "$OUTPUT_TYP"

# Table column widths are handled by the Lua filter (fix-tables.lua) at pandoc
# AST level — no sed fixups needed.  The filter matches tables by header cell
# content and overrides pandoc-computed widths with hand-tuned values.

# Fix mermaid diagram images — pandoc wraps in #box(image(...)) with no width; add width and center
# Constrain diagrams: use height for tall vertical diagrams, width for others
sed -i 's|#box(image("\.mermaid-tmp/diagram-2\.png"))|#align(center)[#image(".mermaid-tmp/diagram-2.png", height: 90%)]|' "$OUTPUT_TYP"
sed -i 's|#box(image("\.mermaid-tmp/diagram-3\.png"))|#align(center)[#image(".mermaid-tmp/diagram-3.png", width: 90%)]|' "$OUTPUT_TYP"
sed -i 's|#box(image("\(\.mermaid-tmp/diagram-[0-9]*\.png\)"))|#align(center)[#image("\1", width: 75%)]|g' "$OUTPUT_TYP"

if [[ "${1:-}" == "--pdf" ]]; then
    echo "Compiling PDF..."
    mkdir -p "$(dirname "$OUTPUT_PDF")"
    cd "$SCRIPT_DIR"
    typst compile --root "$PROJECT_ROOT" "$OUTPUT_TYP" "$OUTPUT_PDF"
    echo "  -> $OUTPUT_PDF"
    echo "  $(wc -c < "$OUTPUT_PDF" | xargs) bytes"
fi

echo "Done."

# Clean up mermaid temp files
rm -rf "$MERMAID_DIR"
