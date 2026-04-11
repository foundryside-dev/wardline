#!/bin/bash
# Shared build helpers for the Wardline PDF pipeline.
#
# Sourced by build-spec.sh and build-lite.sh.  All functions assume
# SCRIPT_DIR and PROJECT_ROOT are set by the caller.

# ─────────────────────────────────────────────────────────────
# Toolchain version checks — fail fast if anything is missing.
# ─────────────────────────────────────────────────────────────
wl_check_toolchain() {
    local min_pandoc="3.0"
    local min_typst="0.14"

    command -v pandoc >/dev/null 2>&1 || { echo "[error] pandoc not found on PATH" >&2; exit 1; }
    command -v typst  >/dev/null 2>&1 || { echo "[error] typst not found on PATH"  >&2; exit 1; }
    command -v mmdc   >/dev/null 2>&1 || { echo "[error] mmdc (mermaid-cli) not found on PATH" >&2; exit 1; }
    command -v python3 >/dev/null 2>&1 || { echo "[error] python3 not found on PATH" >&2; exit 1; }

    local pandoc_ver
    pandoc_ver="$(pandoc --version | head -1 | grep -oP '[\d.]+' | head -1)"
    if ! printf '%s\n%s\n' "$min_pandoc" "$pandoc_ver" | sort -V -C 2>/dev/null; then
        echo "[error] pandoc >= $min_pandoc required (found $pandoc_ver)" >&2
        exit 1
    fi

    local typst_ver
    typst_ver="$(typst --version 2>/dev/null | grep -oP '[\d.]+' | head -1)"
    if [[ -z "$typst_ver" ]]; then
        echo "[error] could not parse typst version" >&2
        exit 1
    fi
    if ! printf '%s\n%s\n' "$min_typst" "$typst_ver" | sort -V -C 2>/dev/null; then
        echo "[error] typst >= $min_typst required (found $typst_ver)" >&2
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────
# Concatenate an ordered list of chapters into a single file.
#   $1 — destination file (will be overwritten)
#   $2 — source directory
#   remaining args — chapter filenames
# ─────────────────────────────────────────────────────────────
wl_concat_chapters() {
    local dest="$1"; shift
    local src_dir="$1"; shift
    : > "$dest"
    local chapter
    for chapter in "$@"; do
        local src="$src_dir/$chapter"
        if [[ ! -f "$src" ]]; then
            echo "  [error] Missing chapter: $chapter" >&2
            exit 1
        fi
        cat "$src" >> "$dest"
        printf '\n\n\n' >> "$dest"
    done
}

# ─────────────────────────────────────────────────────────────
# Run pandoc with the standard Wardline template + filter set.
#   $1 — input markdown
#   $2 — output .typ
#   $3 — metadata yaml
# ─────────────────────────────────────────────────────────────
wl_run_pandoc() {
    local input="$1"
    local output="$2"
    local metadata="$3"
    pandoc "$input" \
        --from=markdown \
        --to=typst \
        --template="$SCRIPT_DIR/template.typ" \
        --metadata-file="$metadata" \
        --lua-filter="$SCRIPT_DIR/fix-tables.lua" \
        --standalone \
        --columns=120 \
        -o "$output"
    # Pandoc emits per-cell alignment on every table — the template's
    # `set table(align: left)` already handles alignment uniformly.
    sed -i '/^    align: ([^)]*),$/d' "$output"
}

# ─────────────────────────────────────────────────────────────
# Compile a .typ intermediate to PDF.
#   $1 — .typ file
#   $2 — output PDF path
# ─────────────────────────────────────────────────────────────
wl_compile_pdf() {
    local input="$1"
    local output="$2"
    mkdir -p "$(dirname "$output")"
    (
        cd "$SCRIPT_DIR"
        typst compile --root "$PROJECT_ROOT" "$input" "$output"
    )
}

# ─────────────────────────────────────────────────────────────
# Produce a temporary metadata file with the ``date`` field
# computed at build time unless FORCE_DATE is set in the env.
#   $1 — source metadata yaml
#   $2 — destination metadata yaml
# ─────────────────────────────────────────────────────────────
wl_stamp_date() {
    local src="$1"
    local dest="$2"
    local build_date
    if [[ -n "${FORCE_DATE:-}" ]]; then
        build_date="$FORCE_DATE"
    else
        build_date="$(date '+%-d %B %Y')"
    fi
    awk -v d="$build_date" '
        BEGIN { set = 0 }
        /^date:/ && !set { print "date: \"" d "\""; set = 1; next }
        { print }
    ' "$src" > "$dest"
}
