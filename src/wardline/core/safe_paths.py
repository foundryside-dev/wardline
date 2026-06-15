"""Path guards for fixed project-local read/write targets."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from wardline.core.errors import WardlineError


def safe_project_path(root: Path, target: Path, *, label: str | None = None) -> Path:
    """Return ``target`` only if writes to it stay under ``root``.

    Fixed install/write targets must not follow a final symlink out of a project.
    Parent-directory symlink escapes are also rejected by resolving the candidate
    path before writing.
    """
    root_resolved = root.resolve()
    candidate = target if target.is_absolute() else root_resolved / target
    name = label or candidate.name
    if candidate.is_symlink():
        raise WardlineError(f"{name}: refusing to write through a symlink")
    resolved = candidate.resolve(strict=False)
    if not (resolved == root_resolved or resolved.is_relative_to(root_resolved)):
        raise WardlineError(f"{name}: resolved path escapes project root {root_resolved}")
    parent = candidate.parent.resolve(strict=False)
    if not (parent == root_resolved or parent.is_relative_to(root_resolved)):
        raise WardlineError(f"{name}: parent directory escapes project root {root_resolved}")
    return candidate


def safe_project_file(root: Path, target: Path, *, label: str | None = None) -> Path:
    """Return ``target`` only if file writes to it stay under ``root``."""
    return safe_project_path(root, target, label=label)


def safe_write_text(root: Path, target: Path, content: str, *, label: str | None = None) -> None:
    """Safely write ``content`` to ``target`` under ``root``, resolving symlinks and boundary checks."""
    safe_path = safe_project_file(root, target, label=label)
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    _write_text_no_follow(safe_path, content, label=label or safe_path.name)


def write_text_no_follow(target: Path, content: str, *, label: str | None = None) -> None:
    """Write ``content`` without following a final-component symlink."""
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_text_no_follow(target, content, label=label or target.name)


def _write_text_no_follow(path: Path, content: str, *, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o666)
    except OSError as exc:
        if path.is_symlink():
            raise WardlineError(f"{label}: refusing to write through a symlink") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


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


def read_bytes_no_follow(path: Path) -> bytes | None:
    """Read ``path`` as bytes without following a final-component symlink.

    Path-based twin of :func:`write_text_no_follow` (no ``root`` join — the caller owns
    a concrete in-state path). Returns ``None`` for a missing, symlinked, non-regular,
    or unreadable target, so a checkout that plants one of wardline's own state files as
    a symlink can neither make wardline follow it off-box nor crash. Used for the
    byte-identical store snapshot, where text decoding is not acceptable."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            return None
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            return handle.read()
    except OSError:
        return None
