"""Timestamped scan artifact paths and retention."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.errors import WardlineError
from wardline.core.paths import artifacts_dir as _artifacts_dir_for
from wardline.core.paths import project_root_for
from wardline.core.safe_paths import safe_project_path

_FORMAT_SUFFIXES = {
    "jsonl": "findings.jsonl",
    "sarif": "findings.sarif",
    "agent-summary": "findings.agent-summary.json",
    "legis": "scan.legis.json",
}
_MAX_COLLISION_RETRIES = 1000


def artifact_suffix(fmt: str) -> str:
    try:
        return _FORMAT_SUFFIXES[fmt]
    except KeyError as exc:
        raise WardlineError(f"unsupported scan artifact format: {fmt}") from exc


def timestamped_scan_artifact(root: Path, fmt: str, config: WardlineConfig) -> Path:
    proj_root = project_root_for(root)
    artifact_dir = _artifact_dir(root, config)
    suffix = artifact_suffix(fmt)
    for candidate in _timestamped_candidates(proj_root, artifact_dir, suffix):
        if not candidate.exists():
            return candidate
    raise WardlineError(f"{suffix}: could not allocate a unique scan artifact name")


def write_scan_artifact(root: Path, fmt: str, config: WardlineConfig, content: str) -> Path:
    """Write a default scan artifact with exclusive create and retention."""
    proj_root = project_root_for(root)
    artifact_dir = _artifact_dir(root, config)
    suffix = artifact_suffix(fmt)
    for candidate in _timestamped_candidates(proj_root, artifact_dir, suffix):
        try:
            _write_text_exclusive(proj_root, candidate, content, label=candidate.name)
        except FileExistsError:
            continue
        prune_scan_artifacts(proj_root, candidate, fmt, config.artifacts.retain)
        return candidate
    raise WardlineError(f"{suffix}: could not allocate a unique scan artifact name")


def prune_scan_artifacts(root: Path, artifact: Path, fmt: str, retain: int) -> None:
    if retain <= 0:
        raise WardlineError("artifacts.retain must be a positive integer")
    root_resolved = root.resolve()
    current = safe_project_path(root_resolved, artifact, label=artifact.name).resolve(strict=False)
    suffix = artifact_suffix(fmt)
    pattern = _managed_artifact_pattern(suffix)
    candidates = sorted(
        (
            path
            for path in artifact.parent.iterdir()
            if pattern.match(path.name) and _is_regular_file_no_follow(path) and path.resolve(strict=False) != current
        ),
        key=lambda path: _managed_artifact_sort_key(path.name, suffix),
    )
    stale = candidates[: max(0, len(candidates) - max(0, retain - 1))]
    for path in stale:
        safe_project_path(root_resolved, path, label=path.name)
        try:
            path.unlink()
        except OSError as exc:
            raise WardlineError(f"{path.name}: failed to prune old scan artifact: {exc}") from exc


def _artifact_dir(root: Path, config: WardlineConfig) -> Path:
    return _artifacts_dir_for(root, config.artifacts.dir)


def _timestamped_candidates(root_resolved: Path, artifact_dir: Path, suffix: str) -> Iterator[Path]:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    yield safe_project_path(root_resolved, artifact_dir / f"{timestamp}-{suffix}", label=suffix)
    for counter in range(1, _MAX_COLLISION_RETRIES):
        yield safe_project_path(root_resolved, artifact_dir / f"{timestamp}-{counter:03d}-{suffix}", label=suffix)


def _managed_artifact_pattern(suffix: str) -> re.Pattern[str]:
    return re.compile(rf"^(?P<stamp>\d{{8}}T\d{{6}}Z)(?:-(?P<counter>\d{{3}}))?-{re.escape(suffix)}$")


def _managed_artifact_sort_key(name: str, suffix: str) -> tuple[str, int, str]:
    match = _managed_artifact_pattern(suffix).match(name)
    if match is None:
        return (name, -1, name)
    counter = int(match.group("counter") or "0")
    return (match.group("stamp"), counter, name)


def _is_regular_file_no_follow(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False


def _write_text_exclusive(root: Path, target: Path, content: str, *, label: str) -> None:
    safe_path = safe_project_path(root, target, label=label)
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(safe_path, flags, 0o666)
    except FileExistsError:
        raise
    except OSError as exc:
        if safe_path.is_symlink():
            raise WardlineError(f"{label}: refusing to write through a symlink") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
