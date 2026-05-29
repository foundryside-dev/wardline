# src/wardline/core/discovery.py
"""Discover Python source files under configured roots (stdlib-only)."""

from __future__ import annotations

import fnmatch
import warnings
from collections.abc import Iterable
from pathlib import Path

from wardline.core.config import WardlineConfig

_ALWAYS_SKIP = frozenset({"__pycache__", ".venv", "venv", ".git", ".mypy_cache"})


def discover(root: Path, config: WardlineConfig) -> list[Path]:
    root = root.resolve()
    found: list[Path] = []
    for src in config.source_roots:
        base = (root / src).resolve()
        if not base.exists():
            warnings.warn(f"source root does not exist: {base}", stacklevel=2)
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in _ALWAYS_SKIP for part in path.parts):
                continue
            relposix = (
                path.relative_to(root).as_posix()
                if path.is_relative_to(root)
                else path.as_posix()
            )
            if _excluded(relposix, config.exclude):
                continue
            found.append(path)
    return found


def _excluded(relposix: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(relposix, pattern) for pattern in patterns)
