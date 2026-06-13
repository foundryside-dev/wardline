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
from wardline.core.gitignore import GitignoreMatcher

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
        ".eggs",
        "build",
        "dist",
    }
)

# Glob-shaped floor entries (matched against a single directory NAME, not a path).
# ``*.egg-info`` is the canonical packaging-metadata tree that bloats a project-root
# scan; it is a name pattern, so it cannot live in the exact-name ``_ALWAYS_SKIP`` set.
_ALWAYS_SKIP_GLOBS = ("*.egg-info",)


def _is_floored_dir(name: str, skip_dirs: frozenset[str]) -> bool:
    return name in skip_dirs or any(fnmatch.fnmatch(name, pat) for pat in _ALWAYS_SKIP_GLOBS)


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
    # Read the project-root .gitignore ONCE so a multi-GB gitignored tree (third-party
    # deps, build output) is never descended. Per-directory .gitignore files are layered
    # in as the top-down walk reaches them, mirroring git's nested-ignore semantics. The
    # base is an empty matcher (not None) so a project with ONLY nested .gitignore files
    # still gets directory pruning.
    root_gitignore = root / ".gitignore"
    root_ignore = (
        GitignoreMatcher.from_file(root_gitignore) if root_gitignore.is_file() else GitignoreMatcher.empty()
    )
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
        ignore_under_root = root_ignore if base.is_relative_to(root) else None
        # Per-directory ignore layers, keyed by the dir's POSIX path relative to root.
        dir_ignores: dict[str, GitignoreMatcher] = {}
        candidates: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(base):
            current = Path(dirpath)
            ignore = _ignore_for(current, root, ignore_under_root, dir_ignores)
            kept: list[str] = []
            for dirname in sorted(dirnames):
                if _is_floored_dir(dirname, skip_dirs):
                    continue
                if ignore is not None and _gitignored_dir(current / dirname, root, ignore):
                    continue
                kept.append(dirname)
            dirnames[:] = kept
            for filename in sorted(filenames):
                if any(filename.endswith(suffix) for suffix in suffixes):
                    candidates.append(current / filename)
        for path in candidates:
            rel_parts = path.relative_to(base).parts if path.is_relative_to(base) else path.parts
            if any(_is_floored_dir(part, skip_dirs) for part in rel_parts):
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


def _ignore_for(
    current: Path,
    root: Path,
    base_ignore: GitignoreMatcher | None,
    dir_ignores: dict[str, GitignoreMatcher],
) -> GitignoreMatcher | None:
    """Return the effective gitignore matcher for ``current``: the root .gitignore
    layered with every parent-directory .gitignore reached so far, plus ``current``'s
    own. Returns ``None`` when the directory is outside the gitignore base (root)."""
    if base_ignore is None or not current.is_relative_to(root):
        return None
    relposix = current.relative_to(root).as_posix()
    if relposix in dir_ignores:
        return dir_ignores[relposix]
    if relposix in (".", ""):
        parent_matcher = base_ignore
    else:
        parent_rel = current.parent.relative_to(root).as_posix()
        parent_matcher = dir_ignores.get(parent_rel, base_ignore)
    local = current / ".gitignore"
    matcher = parent_matcher.extend(GitignoreMatcher.from_file(local)) if local.is_file() else parent_matcher
    dir_ignores[relposix] = matcher
    return matcher


def _gitignored_dir(child: Path, root: Path, ignore: GitignoreMatcher) -> bool:
    if not child.is_relative_to(root):
        return False
    return ignore.match(child.relative_to(root).as_posix(), is_dir=True)


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
