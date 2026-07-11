"""Path guards for fixed project-local read/write targets."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

from wardline.core.confinement import SourceRootConfinement
from wardline.core.errors import WardlineError

_OPENAT_SUPPORTED = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd


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


def explicit_output_target(root: Path, target: Path, *, cwd: Path | None = None) -> tuple[Path, Path | None]:
    """Return the concrete explicit output target and its project guard root.

    Relative explicit outputs belong to the caller's CWD. If the target is inside
    ``root`` or reaches ``root`` through an existing symlink prefix, return the
    scan root as a guard so parent symlink escapes are rejected. Explicit outside
    targets keep no-follow-only behavior.
    """
    base = cwd or Path.cwd()
    root_abs = _absolute_no_symlinks(root, base)
    target_abs = _absolute_no_symlinks(target, base)
    root_resolved = root.resolve()
    if (
        _is_relative_to(target_abs, root_abs)
        or _is_relative_to(target_abs, root_resolved)
        or _path_enters_root(target, root_resolved, cwd=base)
    ):
        return target_abs, root_resolved
    return target, None


def write_explicit_output_text(root: Path, target: Path, content: str, *, label: str | None = None) -> None:
    """Write explicit command output with project-root guarding when it lands in ``root``."""
    safe_target, safe_root = explicit_output_target(root, target)
    name = label or safe_target.name
    if safe_root is not None:
        safe_write_text(safe_root, safe_target, content, label=name)
    else:
        write_text_no_follow(safe_target, content, label=name)


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


def _absolute_no_symlinks(path: Path, cwd: Path) -> Path:
    candidate = path if path.is_absolute() else cwd / path
    return Path(os.path.abspath(os.fspath(candidate)))


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _path_enters_root(path: Path, root: Path, *, cwd: Path) -> bool:
    if path.is_absolute():
        current = Path(path.anchor)
        parts = path.parts[1:]
    else:
        current = cwd
        parts = path.parts
    for part in parts:
        if part in {"", "."}:
            continue
        current = current / part
        try:
            resolved = current.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved == root or _is_relative_to(resolved, root):
            return True
    return False


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


def read_source_bytes(
    path: Path,
    *,
    root: Path,
    source_root_confinement: SourceRootConfinement,
) -> bytes:
    """Read one regular source file from a descriptor pinned to its validated inode.

    Secure scans normalize the candidate lexically beneath a strictly resolved root,
    then traverse every component relative to pinned directory descriptors. Legacy
    scans intentionally permit regular outside paths, but both policies reject a final
    symlink and pathname swaps around ``open``. The source descriptor is read only after
    the pre-open, opened, and post-open identities agree, so later path replacement
    cannot redirect the bytes consumed by an analyzer.
    """
    if not source_root_confinement.confines_to_project:
        return _read_legacy_source_bytes(path)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY") or not _OPENAT_SUPPORTED:
        raise OSError(errno.ENOTSUP, "secure source reads require openat/stat dir_fd and no-follow support", path)

    try:
        resolved_root = root.resolve(strict=True)
    except RuntimeError as exc:
        raise OSError(errno.ELOOP, f"project root resolution failed: {root}", root) from exc
    candidate = path if path.is_absolute() else resolved_root / path
    candidate = Path(os.path.abspath(os.fspath(candidate)))
    try:
        relative = candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise OSError(errno.EPERM, f"source path is lexically outside project root: {path}", path) from exc
    if not relative.parts:
        raise OSError(errno.EINVAL, f"source path names the project directory: {path}", path)

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    directory_fds: list[int] = []
    try:
        anchor = Path(resolved_root.anchor)
        if not resolved_root.is_absolute() or not anchor.anchor:
            raise OSError(errno.ENOTSUP, f"project root has no stable absolute anchor: {resolved_root}", root)
        anchor_before = anchor.stat(follow_symlinks=False)
        anchor_fd = os.open(anchor, directory_flags)
        directory_fds.append(anchor_fd)
        anchor_opened = os.fstat(anchor_fd)
        anchor_after = anchor.stat(follow_symlinks=False)
        if not (
            stat.S_ISDIR(anchor_opened.st_mode)
            and os.path.samestat(anchor_before, anchor_opened)
            and os.path.samestat(anchor_opened, anchor_after)
        ):
            raise OSError(errno.ESTALE, f"filesystem anchor changed while opening: {anchor}", anchor)

        root_fd = _open_verified_directory_components(
            anchor_fd,
            resolved_root.relative_to(anchor).parts,
            flags=directory_flags,
            opened_fds=directory_fds,
            subject=resolved_root,
        )
        parent_fd = _open_verified_directory_components(
            root_fd,
            relative.parts[:-1],
            flags=directory_flags,
            opened_fds=directory_fds,
            subject=path,
        )

        final = relative.parts[-1]
        before = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, f"source path is not a regular file: {path}", path)
        source_fd = os.open(final, file_flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(source_fd)
            after = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
            if not (
                stat.S_ISREG(opened.st_mode) and os.path.samestat(before, opened) and os.path.samestat(opened, after)
            ):
                raise OSError(errno.ESTALE, f"source path changed while opening: {path}", path)
            with os.fdopen(source_fd, "rb") as handle:
                source_fd = -1
                return handle.read()
        finally:
            if source_fd >= 0:
                os.close(source_fd)
    finally:
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _open_verified_directory_components(
    parent_fd: int,
    components: tuple[str, ...],
    *,
    flags: int,
    opened_fds: list[int],
    subject: Path,
) -> int:
    """Traverse directory components under a pinned parent and verify every hop."""
    current_fd = parent_fd
    for component in components:
        before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise OSError(errno.ENOTDIR, f"path component is not a directory: {component}", subject)
        child_fd = os.open(component, flags, dir_fd=current_fd)
        opened_fds.append(child_fd)
        opened = os.fstat(child_fd)
        after = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
        if not (stat.S_ISDIR(opened.st_mode) and os.path.samestat(before, opened) and os.path.samestat(opened, after)):
            raise OSError(errno.ESTALE, f"path component changed while opening: {component}", subject)
        current_fd = child_fd
    return current_fd


def _read_legacy_source_bytes(path: Path) -> bytes:
    """Legacy outside-root read: full pathname, regular final component, no-follow when available."""
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, f"source path is not a regular file: {path}", path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = path.stat(follow_symlinks=False)
        if not (os.path.samestat(before, opened) and os.path.samestat(opened, after)):
            raise OSError(errno.ESTALE, f"source path changed while opening: {path}", path)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)
