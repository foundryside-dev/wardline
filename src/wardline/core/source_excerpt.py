# src/wardline/core/source_excerpt.py
"""Path-contained source excerpts for the triage judge (SP5).

The single chokepoint between local source bytes and the third-party LLM. The
resolved path MUST stay under the scan root (we are shipping bytes off-box); an
escape is a hard error. No secrets-scrubbing (documented spec limitation §5.1).
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.errors import DiscoveryError

_DEFAULT_CHAR_LIMIT = 12_000


def extract_excerpt(
    root: Path, path: str, *, line: int, context_lines: int, char_limit: int = _DEFAULT_CHAR_LIMIT
) -> str:
    """Return ``line ± context_lines`` of ``root/path`` with 1-based gutters, char-capped.

    Raises ``DiscoveryError`` if the resolved path escapes ``root`` or is unreadable.
    """
    root_resolved = root.resolve()
    target = (root_resolved / path).resolve()
    if not target.is_relative_to(root_resolved):
        raise DiscoveryError(f"excerpt path {path!r} escapes scan root {root_resolved}")
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise DiscoveryError(f"cannot read {path!r} for excerpt: {exc}") from exc
    lo = max(0, line - 1 - context_lines)
    hi = min(len(lines), line + context_lines)
    gutter = [f"{n + 1}: {lines[n]}" for n in range(lo, hi)]
    text = "\n".join(gutter)
    return text if len(text) <= char_limit else text[:char_limit]
