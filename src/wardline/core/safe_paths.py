"""Path guards for fixed project-local read/write targets."""

from __future__ import annotations

import stat
from pathlib import Path

from wardline.core.errors import WardlineError


def safe_project_file(root: Path, target: Path, *, label: str | None = None) -> Path:
    """Return ``target`` only if writes to it stay under ``root``.

    Fixed install/write targets must not follow a final symlink out of a project.
    Parent-directory symlink escapes are also rejected by resolving the candidate
    path before writing.
    """
    root_resolved = root.resolve()
    candidate = target if target.is_absolute() else root_resolved / target
    name = label or candidate.name
    if candidate.exists() and candidate.is_symlink():
        raise WardlineError(f"{name}: refusing to write through a symlink")
    resolved = candidate.resolve(strict=False)
    if not (resolved == root_resolved or resolved.is_relative_to(root_resolved)):
        raise WardlineError(f"{name}: resolved path escapes project root {root_resolved}")
    parent = candidate.parent.resolve(strict=False)
    if not (parent == root_resolved or parent.is_relative_to(root_resolved)):
        raise WardlineError(f"{name}: parent directory escapes project root {root_resolved}")
    return candidate


def safe_write_text(root: Path, target: Path, content: str, *, label: str | None = None) -> None:
    """Safely write ``content`` to ``target`` under ``root``, resolving symlinks and boundary checks."""
    safe_path = safe_project_file(root, target, label=label)
    safe_path.write_text(content, encoding="utf-8")


def safe_read_text_if_regular(
    root: Path,
    target: Path,
    *,
    label: str | None = None,
    encoding: str = "utf-8",
) -> str | None:
    """Read an optional fixed project file only when it is a regular in-root file.

    Returns ``None`` for missing, symlinked, non-regular, escaping, unreadable, or
    undecodable paths. This is for fail-soft discovery/config rungs such as
    sibling ``ephemeral.port`` files, where an attacker-controlled repository must
    not be able to make Wardline block on a FIFO/device or follow a symlink.
    """
    try:
        safe_path = safe_project_file(root, target, label=label)
        if not stat.S_ISREG(safe_path.stat(follow_symlinks=False).st_mode):
            return None
        return safe_path.read_text(encoding=encoding)
    except (OSError, UnicodeDecodeError, WardlineError):
        return None
