# src/wardline/core/discovery.py
"""Discover Python source files under configured roots (stdlib-only)."""

from __future__ import annotations

import fnmatch
import os
import warnings
from collections.abc import Iterable
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.errors import ConfigError

_ALWAYS_SKIP = frozenset(
    {
        "__pycache__",
        ".venv",
        "venv",
        ".git",
        ".mypy_cache",
        ".uv-cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "node_modules",
    }
)


def discover(
    root: Path,
    config: WardlineConfig,
    *,
    confine_to_root: bool = False,
    suffixes: frozenset[str] = frozenset({".py"}),
) -> list[Path]:
    """Discover source files under the configured roots.

    ``suffixes`` selects the language: the default ``{".py"}`` is byte-identical to
    the original Python-only sweep; a Rust frontend passes ``{".rs"}``. Files across
    all requested suffixes are gathered and yielded in one combined sorted order, so
    finding/entity order stays deterministic and the single-suffix Python case is
    unchanged.
    """
    root = root.resolve()
    # `target` is cargo build output — skip it only in `.rs` mode. It is a legitimate
    # Python package name, so adding it to the global skip set would silently under-scan
    # Python projects (the very failure wardline surfaces loudly elsewhere).
    skip_dirs = _ALWAYS_SKIP | {"target"} if ".rs" in suffixes else _ALWAYS_SKIP
    found: list[Path] = []
    for src in config.source_roots:
        base = (root / src).resolve()
        if confine_to_root and not base.is_relative_to(root):
            # A poisoned in-root weft.toml whose source_roots escape the root
            # would otherwise read out-of-root source. Reject (do NOT silently
            # skip — a silent skip under-scans and gives a false all-clear).
            raise ConfigError(
                f"source_root {src!r} resolves outside the project root; refusing to scan outside the root"
            )
        if not base.exists():
            warnings.warn(f"source root does not exist: {base}", stacklevel=2)
            continue
        candidates: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(dirname for dirname in dirnames if dirname not in skip_dirs)
            current = Path(dirpath)
            for filename in sorted(filenames):
                if any(filename.endswith(suffix) for suffix in suffixes):
                    candidates.append(current / filename)
        for path in candidates:
            rel_parts = path.relative_to(base).parts if path.is_relative_to(base) else path.parts
            if any(part in skip_dirs for part in rel_parts):
                continue
            if confine_to_root and not path.resolve().is_relative_to(root):
                # A *.py symlink inside a legitimate source_root can point at an
                # out-of-root target (rglob does not descend directory symlinks,
                # so only file symlinks leak). Refuse to read out-of-root content
                # by skipping it — the MCP confinement guarantee (THREAT-001).
                relposix = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
                warnings.warn(f"WLN-ENGINE-FILE-SKIPPED: {relposix}", stacklevel=2)
                continue
            relposix = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
            if _excluded(relposix, config.exclude):
                continue
            found.append(path)
    return found


def missing_source_roots(root: Path, config: WardlineConfig, *, confine_to_root: bool = False) -> list[str]:
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
