from __future__ import annotations

import subprocess
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.errors import WardlineError

if TYPE_CHECKING:
    from wardline.scanner.index import Entity

_SAFE_GIT_CONFIG = ("-c", "core.fsmonitor=false")


def get_changed_files_since(ref: str, root: Path) -> set[str]:
    """Get the set of file paths (repo-relative, POSIX-style matching Location.path)
    that have changed since `ref`, including staged, unstaged, and untracked changes.
    """
    if ref.startswith("-"):
        raise WardlineError("new_since git ref must not begin with '-'")

    # 1. Get the git toplevel directory.
    try:
        res = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        git_toplevel = Path(res.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise WardlineError(
            f"Failed to find Git repository top-level from {root}. "
            "Ensure git is installed and you are in a Git repository."
        ) from exc

    # 2. Resolve ref to a verified object id before passing it to git diff.
    try:
        res = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "rev-parse", "--verify", "--end-of-options", ref],
            cwd=git_toplevel,
            capture_output=True,
            text=True,
            check=True,
        )
        verified_ref = res.stdout.strip().splitlines()[0]
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        raise WardlineError(f"Git ref verification failed for ref {ref!r}: {stderr}") from exc
    if not verified_ref:
        raise WardlineError(f"Git ref verification failed for ref {ref!r}: empty object id")

    # 3. Get changed files since ref (committed since ref, staged, unstaged).
    try:
        res = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "diff", "--name-only", verified_ref, "--"],
            cwd=git_toplevel,
            capture_output=True,
            text=True,
            check=True,
        )
        diff_paths = [p.strip() for p in res.stdout.splitlines() if p.strip()]
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else str(exc)
        raise WardlineError(f"Git diff failed for ref {ref!r}: {stderr}") from exc

    # 4. Get untracked files.
    try:
        res = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "ls-files", "--others", "--exclude-standard"],
            cwd=git_toplevel,
            capture_output=True,
            text=True,
            check=True,
        )
        untracked_paths = [p.strip() for p in res.stdout.splitlines() if p.strip()]
    except subprocess.CalledProcessError:
        untracked_paths = []

    # 5. Map both lists to path relative to `root` (POSIX-style).
    changed_rel = set()
    root_resolved = root.resolve()
    for gp in diff_paths + untracked_paths:
        abs_path = (git_toplevel / gp).resolve()
        try:
            rel = abs_path.relative_to(root_resolved)
            changed_rel.add(rel.as_posix())
        except ValueError:
            # File is outside the scanned root
            pass

    return changed_rel


def get_affected_entities(
    changed_files: set[str],
    entities: Mapping[str, Entity],
    project_edges: Mapping[str, frozenset[str]],
) -> set[str]:
    """Determine the set of affected entities.
    An entity is affected if:
      - It is directly in one of the changed files.
      - It transitively calls any affected entity (caller-side propagation).
    """
    # Start with entities in the changed files.
    affected = set()
    for qualname, entity in entities.items():
        if entity.location.path in changed_files:
            affected.add(qualname)

    # Build reverse call graph: callee -> callers
    reverse_edges: dict[str, set[str]] = {}
    for caller, callees in project_edges.items():
        for callee in callees:
            reverse_edges.setdefault(callee, set()).add(caller)

    # BFS/DFS to find all transitively affected callers
    queue = deque(affected)
    while queue:
        current = queue.popleft()
        for caller in reverse_edges.get(current, []):
            if caller not in affected:
                affected.add(caller)
                queue.append(caller)

    return affected
