#!/usr/bin/env python3
"""Markdown preprocessor for the Wardline PDF pipeline.

Replaces the inline ``python3 -c`` blocks that previously lived in
``build-spec.sh``.  Takes a concatenated Markdown file and applies a
profile-driven sequence of transforms before handing the result to pandoc.

Profiles:
    spec  — full Wardline Framework Specification (19 chapters)
    lite  — Wardline Lite practical guide (single document)

The transforms are deliberately small, composable functions so each can be
unit-tested or bypassed independently.  Output is written in place — the
caller is expected to operate on a temporary copy of the combined markdown.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# Metadata stripping
# ─────────────────────────────────────────────────────────────
# Bold front-matter lines that the Typst template already renders on the
# title page.  Matching these by literal prefix is brittle (a new field
# breaks silently) but the set is small and stable; a frontmatter block
# delimiter would be more robust if the list grows.
_METADATA_PREFIXES = (
    "**Date:**",
    "**Status:**",
    "**Protective Marking:**",
    "**Prepared by:**",
    "**Document type:**",
    "**Parent paper:**",
    "**Language bindings:**",
    "**Classification:**",
)

_METADATA_CONTAINS = (
    "Digital Transformation Agency",
)


def strip_metadata_lines(text: str) -> str:
    out = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if any(stripped.startswith(p) for p in _METADATA_PREFIXES):
            continue
        if any(s in line for s in _METADATA_CONTAINS):
            continue
        out.append(line)
    return "".join(out)


def strip_standalone_hrules(text: str) -> str:
    """Remove standalone ``---`` lines — Typst sections provide structure."""
    return re.sub(r"(?m)^---\s*$\n?", "", text)


# ─────────────────────────────────────────────────────────────
# Table-of-contents stripping (spec only)
# ─────────────────────────────────────────────────────────────
_TOC_PATTERN = re.compile(
    r"### Contents\n.*?(?=### \d+\.|## Part II)",
    re.DOTALL,
)


def strip_manual_toc(text: str) -> str:
    """Delete the hand-authored Contents list — Typst ``#outline()`` rebuilds it."""
    return _TOC_PATTERN.sub("", text)


# ─────────────────────────────────────────────────────────────
# Admonition conversion (spec only)
# ─────────────────────────────────────────────────────────────
# mkdocs-style ``!!! type "title"`` blocks → plain blockquotes that pandoc
# can render.  Body lines are 4-space indented in the source.
_ADMONITION_PATTERN = re.compile(
    r'^!!! +(\w+) *(?:"([^"]*)")?\n((?:    .*\n|\n)*)',
    re.MULTILINE,
)


def _convert_admonition(m: re.Match[str]) -> str:
    atype = m.group(1)
    title = m.group(2) or atype.capitalize()
    body = m.group(3)
    lines: list[str] = []
    for line in body.split("\n"):
        if line.startswith("    "):
            lines.append("> " + line[4:])
        elif line.strip() == "":
            lines.append(">")
        else:
            lines.append("> " + line)
    body_text = "\n".join(lines).lstrip("> ")
    while body_text.endswith("\n>"):
        body_text = body_text[:-2]
    return f"> **{title}.**\n>\n> {body_text.rstrip()}\n\n"


def convert_admonitions(text: str) -> str:
    return _ADMONITION_PATTERN.sub(_convert_admonition, text)


# ─────────────────────────────────────────────────────────────
# Mermaid rendering
# ─────────────────────────────────────────────────────────────
# PDF-only sizing hints are placed on a dedicated HTML comment line
# immediately preceding the fence.  HTML comments are invisible to
# mkdocs and GitHub rendering, so the web view is unaffected:
#
#     <!-- wl-pdf: size="height: 90%" alt="Authority tier model" -->
#     ```mermaid
#     ...
#     ```
#
# Supported attributes:
#   size    — a Typst image sizing expression (default ``width: 75%``)
#   orient  — ``vertical`` (default) pre-flips ``graph LR`` to ``graph TB``
#             before rendering; ``preserve`` keeps horizontal orientation.
#   alt     — alternative text for accessibility (PDF/UA compliance)
#
# The parser is a small key="value" matcher.
_MERMAID_FENCE = re.compile(
    r"(?:^<!-- wl-pdf:(?P<directive>[^\n]*)-->\s*\n)?"
    r"^```mermaid\s*\n(?P<body>.*?)^```",
    re.DOTALL | re.MULTILINE,
)
_ATTR_PAIR = re.compile(r'(\w+)="([^"]*)"')


@dataclass
class MermaidOptions:
    size: str = "width: 75%"
    orient: str = "vertical"
    alt: str = ""

    @classmethod
    def parse(cls, raw: str) -> "MermaidOptions":
        attrs = dict(_ATTR_PAIR.findall(raw or ""))
        return cls(
            size=attrs.get("size", "width: 75%"),
            orient=attrs.get("orient", "vertical"),
            alt=attrs.get("alt", ""),
        )


def render_mermaid_blocks(
    text: str,
    mermaid_dir: Path,
    relative_base: Path,
) -> str:
    """Render every ``mermaid`` fence to high-resolution PNG for Typst.

    Diagrams are rendered through ``mmdc`` (mermaid-cli) at 4× scale for
    print-quality output (~300 DPI). While SVG would be ideal, Typst's SVG
    renderer doesn't fully support mermaid's foreignObject text rendering.
    If the rendering fails the fence is left in place so the build surfaces
    the problem.
    """
    mermaid_dir.mkdir(parents=True, exist_ok=True)
    counter = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal counter
        counter += 1
        opts = MermaidOptions.parse(match.group("directive") or "")
        code = match.group("body")
        if opts.orient == "vertical":
            code = re.sub(r"(?m)^graph LR$", "graph TB", code)

        mmd_file = mermaid_dir / f"diagram-{counter}.mmd"
        png_file = mermaid_dir / f"diagram-{counter}.png"
        mmd_file.write_text(code)

        try:
            subprocess.run(
                [
                    "mmdc",
                    "-i", str(mmd_file),
                    "-o", str(png_file),
                    "-b", "white",
                    "-t", "neutral",
                    "-s", "4",  # 4× scale for ~300 DPI print quality
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            sys.stderr.write(
                f"  [warn] mermaid render failed for diagram-{counter}: {e}\n"
            )
            return match.group(0)

        if not png_file.exists():
            sys.stderr.write(f"  [warn] mermaid output missing for diagram-{counter}\n")
            return match.group(0)

        rel_path = os.path.relpath(png_file, relative_base)
        sys.stderr.write(f"  Rendered {rel_path} ({opts.size})\n")
        # Emit a raw Typst passthrough block wrapped in #figure(kind: image)
        # for numbered figure support and List of Figures generation.
        # The alt text becomes the figure caption.
        alt_attr = f', alt: "{opts.alt}"' if opts.alt else ""
        caption = f", caption: [{opts.alt}]" if opts.alt else ""
        return (
            "```{=typst}\n"
            f'#figure(kind: image{caption})[#image("{rel_path}", {opts.size}{alt_attr})]\n'
            "```\n"
        )

    return _MERMAID_FENCE.sub(replace, text)


# ─────────────────────────────────────────────────────────────
# Heading manipulation (spec only)
# ─────────────────────────────────────────────────────────────
_DOC_HEADINGS_TO_STRIP = (
    "## Wardline Framework Specification",
    "### Semantic Boundary Classification and Enforcement",
    "# Reviewing AI-Generated Code: A Practical Guide",
)


def strip_document_headings(text: str) -> str:
    out = []
    for line in text.splitlines(keepends=True):
        if line.rstrip() in _DOC_HEADINGS_TO_STRIP:
            continue
        out.append(line)
    return "".join(out)


def part2_to_chapter(text: str) -> str:
    """Promote ``## Part II`` → ``# Part II`` so it becomes a chapter break."""
    return re.sub(r"(?m)^## Part II", "# Part II", text)


_HEADING_RE = re.compile(r"^(#{3,})\s")


def promote_headings(text: str, shift: int) -> str:
    """Shift all headings of level ``shift+1`` and above upward by ``shift``.

    ``shift=2`` converts ``### → #``, ``#### → ##``, etc.  We match from level
    3 onward so ``#`` and ``##`` in the source (if any) are left alone.
    """
    out = []
    for line in text.splitlines(keepends=True):
        m = _HEADING_RE.match(line)
        if m:
            old_level = len(m.group(1))
            new_hashes = "#" * max(1, old_level - shift)
            line = new_hashes + line[old_level:]
        out.append(line)
    return "".join(out)


# ─────────────────────────────────────────────────────────────
# Lite-profile specific
# ─────────────────────────────────────────────────────────────
_LITE_SUBTITLE_BLOCK = re.compile(
    r"^\*\*What you need to know.*?\*\*\s*\n\s*\n---\s*\n",
    re.MULTILINE | re.DOTALL,
)


def strip_lite_subtitle(text: str) -> str:
    """Remove the hand-authored subtitle paragraph — template provides one."""
    return _LITE_SUBTITLE_BLOCK.sub("", text, count=1)


# ─────────────────────────────────────────────────────────────
# Profile runners
# ─────────────────────────────────────────────────────────────
def run_spec(text: str, mermaid_dir: Path, rel_base: Path) -> str:
    text = strip_metadata_lines(text)
    text = strip_standalone_hrules(text)
    text = strip_manual_toc(text)
    text = convert_admonitions(text)
    text = render_mermaid_blocks(text, mermaid_dir, rel_base)
    text = strip_document_headings(text)
    text = part2_to_chapter(text)
    text = promote_headings(text, shift=2)
    return text


def run_lite(text: str, mermaid_dir: Path, rel_base: Path) -> str:
    text = strip_metadata_lines(text)
    text = strip_lite_subtitle(text)
    text = strip_document_headings(text)
    text = strip_standalone_hrules(text)
    # Lite has no admonitions or mermaid today, but wire the stage up so
    # a future diagram is rendered identically.
    text = convert_admonitions(text)
    text = render_mermaid_blocks(text, mermaid_dir, rel_base)
    return text


PROFILES = {
    "spec": run_spec,
    "lite": run_lite,
}


# ─────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--mermaid-dir",
        type=Path,
        required=True,
        help="Scratch directory for rendered mermaid PNGs.",
    )
    parser.add_argument(
        "--mermaid-rel-base",
        type=Path,
        required=True,
        help="Base path relative to which PNG references are emitted (the "
             "directory containing the final .typ file).",
    )
    args = parser.parse_args(argv)

    text = args.input.read_text()
    transformed = PROFILES[args.profile](text, args.mermaid_dir, args.mermaid_rel_base)
    args.output.write_text(transformed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
