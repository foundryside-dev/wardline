# src/wardline/core/discovery.py
"""Discover Python source files under configured roots (stdlib-only)."""

from __future__ import annotations

import fnmatch
import warnings
from collections.abc import Iterable
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.errors import ConfigError

_ALWAYS_SKIP = frozenset({"__pycache__", ".venv", "venv", ".git", ".mypy_cache"})


def discover(
    root: Path, config: WardlineConfig, *, confine_to_root: bool = False
) -> list[Path]:
    root = root.resolve()
    found: list[Path] = []
    for src in config.source_roots:
        base = (root / src).resolve()
        if confine_to_root and not base.is_relative_to(root):
            # A poisoned in-root wardline.yaml whose source_roots escape the root
            # would otherwise read out-of-root source. Reject (do NOT silently
            # skip — a silent skip under-scans and gives a false all-clear).
            raise ConfigError(
                f"source_root {src!r} resolves outside the project root; "
                "refusing to scan outside the root"
            )
        if not base.exists():
            warnings.warn(f"source root does not exist: {base}", stacklevel=2)
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in _ALWAYS_SKIP for part in path.parts):
                continue
            if confine_to_root and not path.resolve().is_relative_to(root):
                # A *.py symlink inside a legitimate source_root can point at an
                # out-of-root target (rglob does not descend directory symlinks,
                # so only file symlinks leak). Refuse to read out-of-root content
                # by skipping it — the MCP confinement guarantee (THREAT-001).
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


def missing_source_roots(
    root: Path, config: WardlineConfig, *, confine_to_root: bool = False
) -> list[str]:
    """Return the configured ``source_roots`` that do not exist on disk.

    ``discover`` skips a non-existent root with a ``warnings.warn`` (invisible to a
    structured consumer like the MCP agent). ``run_scan`` calls this sibling to turn
    each missing root into a finding so the silent under-scan is surfaced. An
    ESCAPING root (under ``confine_to_root``) is excluded here — that is ``discover``'s
    loud ``ConfigError``, a different case.
    """
    root = root.resolve()
    missing: list[str] = []
    for src in config.source_roots:
        base = (root / src).resolve()
        if confine_to_root and not base.is_relative_to(root):
            continue  # escape is discover()'s ConfigError, not a missing root
        if not base.exists():
            missing.append(src)
    return missing


def _excluded(relposix: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(relposix, pattern) for pattern in patterns)
