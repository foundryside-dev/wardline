"""Render + idempotently inject the hash-fenced wardline instruction block."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_BLOCK_VERSION = "1"

_BODY = (
    "This project uses **wardline** as its trust-boundary gate. Before handing "
    "back code that touches external input, run `wardline scan . --fail-on ERROR` "
    "(exit 0 = clean, 1 = gate tripped, 2 = wardline error) and fix findings at "
    "the boundary, not the sink. The full scan -> explain -> fix -> rescan loop "
    "and the baseline-vs-waiver discipline live in the `wardline-gate` skill and "
    "in `docs/agents.md`."
)

_FENCE_RE = re.compile(
    r"<!-- wardline:instructions:v\d+:[0-9a-f]+ -->.*?<!-- /wardline:instructions -->",
    re.DOTALL,
)


def _body_hash() -> str:
    return hashlib.sha256(_BODY.encode("utf-8")).hexdigest()[:8]


def render_block() -> str:
    return (
        f"<!-- wardline:instructions:v{_BLOCK_VERSION}:{_body_hash()} -->\n"
        f"{_BODY}\n"
        "<!-- /wardline:instructions -->"
    )


def inject_block(file_path: Path) -> str:
    """Create / append / replace the block. Returns created|updated|unchanged."""
    block = render_block()
    if not file_path.exists():
        file_path.write_text(block + "\n", encoding="utf-8")
        return "created"
    text = file_path.read_text(encoding="utf-8")
    match = _FENCE_RE.search(text)
    if match is None:
        sep = "" if text.endswith("\n") else "\n"
        file_path.write_text(f"{text}{sep}\n{block}\n", encoding="utf-8")
        return "updated"
    if match.group(0) == block:
        return "unchanged"
    new = text[: match.start()] + block + text[match.end() :]
    file_path.write_text(new, encoding="utf-8")
    return "updated"
