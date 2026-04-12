#!/usr/bin/env python3
"""Post-pandoc Typst transformations for the Wardline PDF pipeline.

Applies transformations to the generated .typ file that cannot be expressed
in the pandoc template or Lua filters. These are structural changes that
require parsing the Typst output as text.

Transformations:
    1. Rotate severity matrix table to landscape orientation
    2. Strip per-cell alignment directives (template handles alignment globally)
    3. Inject heading labels for clickable cross-references

Usage:
    python3 postprocess.py input.typ output.typ
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# Severity matrix landscape rotation
# ─────────────────────────────────────────────────────────────
def rotate_severity_matrix(content: str) -> str:
    """Wrap the severity matrix table in a landscape page.

    The severity matrix has 10 columns and needs full page width.
    We find the #figure() containing the characteristic header pattern
    and wrap it in #page(flipped: true)[...].
    """
    marker = "table.header([Rule], [Pattern], [Integral], [Assured], [Guarded]"
    idx = content.find(marker)
    if idx <= 0:
        return content

    # Find the enclosing #figure( that contains this table
    fig_start = content.rfind("#figure(", 0, idx)
    if fig_start < 0:
        sys.stderr.write("  [warn] severity matrix marker found but no enclosing #figure\n")
        return content

    # Match balanced parentheses/brackets to find figure end
    depth = 0
    fig_end = -1
    for i in range(fig_start, len(content)):
        ch = content[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth == 0:
                fig_end = i + 1
                break

    if fig_end <= fig_start:
        sys.stderr.write("  [warn] could not find severity matrix figure bounds\n")
        return content

    figure_text = content[fig_start:fig_end]
    replacement = "#page(flipped: true)[\n" + figure_text + "\n]"
    content = content[:fig_start] + replacement + content[fig_end:]
    sys.stderr.write("  Rotated severity matrix to landscape\n")
    return content


# ─────────────────────────────────────────────────────────────
# Add kind: table to figures containing tables
# ─────────────────────────────────────────────────────────────
# Pandoc emits #figure(align(center)[#table(...)]) without kind: table.
# We need kind: table for the template's table numbering to work.
#
# Some figures already have kind: table (Pandoc adds it for captioned tables).
# We also strip any trailing ", kind: table" since we add it at the start.

_FIGURE_TABLE_PATTERN = re.compile(
    r"#figure\(\s*\n\s*align\(center\)\[#table\(",
    re.MULTILINE,
)

# Pandoc sometimes adds ", kind: table" as a trailing argument
_TRAILING_KIND_TABLE = re.compile(r"\s*,\s*kind:\s*table\s*\)", re.MULTILINE)


def add_table_kind_to_figures(content: str) -> str:
    """Add kind: table to figures containing tables, avoiding duplicates."""
    # First, remove any trailing ", kind: table)" and replace with just ")"
    content, strip_count = _TRAILING_KIND_TABLE.subn(")", content)

    # Now add kind: table at the start of all table figures
    result, add_count = _FIGURE_TABLE_PATTERN.subn(
        "#figure(kind: table,\n  align(center)[#table(",
        content,
    )
    if add_count > 0:
        sys.stderr.write(f"  Added kind: table to {add_count} table figures\n")
    if strip_count > 0:
        sys.stderr.write(f"  Stripped {strip_count} trailing kind: table arguments\n")
    return result


# ─────────────────────────────────────────────────────────────
# Strip per-cell alignment directives
# ─────────────────────────────────────────────────────────────
# Pandoc emits per-cell alignment on every table cell:
#     align: (left,),
# The template's `set table(align: left)` handles this globally,
# so these directives are redundant and add visual noise.

_ALIGN_PATTERN = re.compile(r"^    align: \([^)]*\),\n", re.MULTILINE)


def strip_cell_alignments(content: str) -> str:
    """Remove pandoc's per-cell alignment directives."""
    result, count = _ALIGN_PATTERN.subn("", content)
    if count > 0:
        sys.stderr.write(f"  Stripped {count} per-cell alignment directives\n")
    return result


# ─────────────────────────────────────────────────────────────
# Inject heading labels for cross-references
# ─────────────────────────────────────────────────────────────
# Enable clickable §X.Y references by adding <section-X-Y> labels
# to headings. We match the pandoc-generated heading pattern and
# inject a label immediately after.
#
# Pandoc output for headings looks like:
#   = 6. Authority tier model: enforcement specification
#   == 6.1 Trust classification and validation status
#
# We inject labels like:
#   = 6. Authority tier model... <section-6>
#   == 6.1 Trust classification... <section-6-1>

_HEADING_PATTERN = re.compile(
    r"^(=+)\s+(\d+(?:\.\d+)*)\.*\s+(.+)$",
    re.MULTILINE,
)


def inject_heading_labels(content: str) -> str:
    """Add <section-X-Y> labels to numbered headings for cross-references."""
    count = 0

    def replace_heading(m: re.Match[str]) -> str:
        nonlocal count
        hashes = m.group(1)
        number = m.group(2)
        title = m.group(3)
        # Convert "6.1.2" to "section-6-1-2"
        label = "section-" + number.replace(".", "-")
        count += 1
        return f"{hashes} {number}. {title} <{label}>"

    result = _HEADING_PATTERN.sub(replace_heading, content)
    if count > 0:
        sys.stderr.write(f"  Injected {count} heading labels for cross-references\n")
    return result


# ─────────────────────────────────────────────────────────────
# Inject Part labels for Part I / Part II navigation
# ─────────────────────────────────────────────────────────────
# Part headings don't have numbers, so we handle them separately.
#
# Pattern: = Part II — Language Binding Reference
# Inject:  = Part II — Language Binding Reference <part-2>

_PART_PATTERN = re.compile(
    r"^(=)\s+(Part\s+(I{1,3}|IV|V|VI))\s*[—–-]\s*(.+)$",
    re.MULTILINE,
)

_ROMAN_TO_INT = {"I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6}


def inject_part_labels(content: str) -> str:
    """Add <part-N> labels to Part headings."""
    count = 0

    def replace_part(m: re.Match[str]) -> str:
        nonlocal count
        hashes = m.group(1)
        part_text = m.group(2)
        roman = m.group(3)
        title = m.group(4)
        part_num = _ROMAN_TO_INT.get(roman, 0)
        if part_num == 0:
            return m.group(0)
        count += 1
        return f"{hashes} {part_text} — {title} <part-{part_num}>"

    result = _PART_PATTERN.sub(replace_part, content)
    if count > 0:
        sys.stderr.write(f"  Injected {count} part labels for cross-references\n")
    return result


# ─────────────────────────────────────────────────────────────
# Inject appendix labels (A.1, B.3, etc.)
# ─────────────────────────────────────────────────────────────
# Appendix headings use letter prefixes:
#   == A.1 Design history
#   === A.2.1 Where Python falls short
#
# We inject labels like <section-A-1>, <section-A-2-1>

_APPENDIX_HEADING_PATTERN = re.compile(
    r"^(=+)\s+([A-Z](?:\.\d+)+)\s+(.+)$",
    re.MULTILINE,
)


def inject_appendix_labels(content: str) -> str:
    """Add <section-A-X-Y> labels to appendix headings."""
    count = 0

    def replace_appendix(m: re.Match[str]) -> str:
        nonlocal count
        hashes = m.group(1)
        number = m.group(2)  # e.g., "A.1" or "A.2.1"
        title = m.group(3)
        # Convert "A.1.2" to "section-A-1-2"
        label = "section-" + number.replace(".", "-")
        count += 1
        return f"{hashes} {number} {title} <{label}>"

    result = _APPENDIX_HEADING_PATTERN.sub(replace_appendix, content)
    if count > 0:
        sys.stderr.write(f"  Injected {count} appendix labels for cross-references\n")
    return result


# ─────────────────────────────────────────────────────────────
# Strip pandoc auto-generated labels
# ─────────────────────────────────────────────────────────────
# Pandoc generates labels like <what-a-wardline-is> on their own line
# after headings. These overwrite our injected section labels, so we
# remove them. Our <section-X-Y> labels are sufficient for cross-refs.
#
# Pattern: standalone label on its own line, e.g.:
#   = 2. What a Wardline is <section-2>
#   <what-a-wardline-is>        ← remove this line
#
# We only remove labels that follow a heading (to avoid removing
# intentional labels on other content).

_PANDOC_LABEL_AFTER_HEADING = re.compile(
    r"(^=+ .+<section-[^>]+>)\n<[a-z0-9.-]+>$",
    re.MULTILINE,
)

_PANDOC_LABEL_AFTER_APPENDIX = re.compile(
    r"(^=+ [A-Z]\.\d.+<section-[A-Z]-[^>]+>)\n<[a-z0-9.-]+>$",
    re.MULTILINE,
)

_PANDOC_LABEL_AFTER_PART = re.compile(
    r"(^= Part .+<part-\d+>)\n<[a-z0-9.-]+>$",
    re.MULTILINE,
)


def strip_pandoc_heading_labels(content: str) -> str:
    """Remove pandoc's auto-generated heading labels that follow our injected labels."""
    count = 0

    def count_and_keep_first(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return m.group(1)

    content = _PANDOC_LABEL_AFTER_HEADING.sub(count_and_keep_first, content)
    content = _PANDOC_LABEL_AFTER_APPENDIX.sub(count_and_keep_first, content)
    content = _PANDOC_LABEL_AFTER_PART.sub(count_and_keep_first, content)

    if count > 0:
        sys.stderr.write(f"  Stripped {count} pandoc auto-generated heading labels\n")
    return content


# ─────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────
def postprocess(content: str) -> str:
    """Apply all post-pandoc transformations."""
    content = add_table_kind_to_figures(content)
    content = strip_cell_alignments(content)
    content = inject_heading_labels(content)
    content = inject_appendix_labels(content)
    content = inject_part_labels(content)
    content = strip_pandoc_heading_labels(content)
    content = rotate_severity_matrix(content)
    return content


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write(f"Usage: {sys.argv[0]} input.typ output.typ\n")
        return 1

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.exists():
        sys.stderr.write(f"[error] input file not found: {input_path}\n")
        return 1

    content = input_path.read_text()
    result = postprocess(content)
    output_path.write_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
