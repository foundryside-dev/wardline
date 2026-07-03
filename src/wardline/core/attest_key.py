# src/wardline/core/attest_key.py
"""Attest signing-key mint and load.  The secret lives in ``.env`` (conventionally
gitignored) and is never written into any committed file under ``.weft/wardline/``.
Mirrors the discipline of :mod:`wardline.loomweave.config.load_loomweave_token`.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
from pathlib import Path

from wardline.core.errors import WardlineError
from wardline.core.safe_paths import safe_project_file

WARDLINE_ATTEST_KEY_ENV = "WARDLINE_ATTEST_KEY"
_SAFE_GIT_CONFIG = ("-c", "core.fsmonitor=false")


def _git_tracks_path(root: Path, target: Path) -> bool:
    try:
        root_resolved = root.resolve()
        relpath = target.resolve(strict=False).relative_to(root_resolved).as_posix()
        result = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "ls-files", "--error-unmatch", "--", relpath],
            cwd=root_resolved,
            capture_output=True,
            text=True,
        )
    except (OSError, ValueError):
        return False
    return result.returncode == 0


def load_attest_key(root: Path) -> str | None:
    """Return the attest signing secret from the environment, or a
    ``WARDLINE_ATTEST_KEY=<value>`` line in ``root/.env``, or None.
    An already-set environment value always wins.  Mirrors
    :func:`wardline.loomweave.config.load_loomweave_token`."""
    value = os.environ.get(WARDLINE_ATTEST_KEY_ENV)
    if value:
        return value
    env_path = safe_project_file(root, root / ".env", label=".env")
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{WARDLINE_ATTEST_KEY_ENV}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def mint_attest_key(root: Path) -> tuple[str, str]:
    """Ensure a project attest key exists; return ``(key, status)``.

    * If :func:`load_attest_key` already returns a key → ``(key, "present")``.
    * Otherwise generate a 64-hex key via :func:`secrets.token_hex`, append
      ``WARDLINE_ATTEST_KEY="<key>"`` to ``root/.env`` (creating it if absent),
      ensure ``.env`` is listed in ``root/.gitignore``, and return
      ``(key, "minted")``.

    The secret never touches a loosely-readable file: a fresh ``.env`` is created
    ``0o600`` atomically (``os.open`` mode, no chmod-after-write window), and a
    pre-existing ``.env`` is chmod-ed to ``0o600`` *before* the append — if that
    tightening fails, minting refuses (:class:`WardlineError`) rather than writing
    the signing key somewhere other users may read.

    Idempotent: a second call with the same root returns ``"present"`` without
    duplicating the entry.
    """
    existing = load_attest_key(root)
    if existing:
        return existing, "present"

    # --- write to .env --------------------------------------------------
    env_path = safe_project_file(root, root / ".env", label=".env")
    if _git_tracks_path(root, env_path):
        raise WardlineError(
            "refusing to mint WARDLINE_ATTEST_KEY into tracked .env; "
            "untrack .env or pass --no-attest-key and provide WARDLINE_ATTEST_KEY from the environment"
        )

    key = secrets.token_hex(32)
    entry = f'{WARDLINE_ATTEST_KEY_ENV}="{key}"\n'

    if env_path.exists():
        # Tighten a pre-existing .env BEFORE the secret touches disk: appending into a
        # group/world-readable file and chmod-ing afterwards leaves a read window, and a
        # silently-failed chmod would leave the signing key exposed indefinitely. If the
        # mode cannot be restricted, refuse loudly rather than write the secret.
        try:
            os.chmod(env_path, 0o600)
        except OSError as exc:
            raise WardlineError(
                "refusing to write WARDLINE_ATTEST_KEY into .env whose permissions cannot be "
                f"restricted to owner-only (0o600): {exc}; fix the file's ownership/mode or "
                "provide WARDLINE_ATTEST_KEY from the environment"
            ) from exc
        if not env_path.read_text(encoding="utf-8").endswith("\n"):
            entry = "\n" + entry

    # Create-or-append through a descriptor opened with mode 0o600 so a FRESH .env is
    # never readable by other users, even for an instant — no chmod-after-write window.
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, entry.encode("utf-8"))
    finally:
        os.close(fd)

    # --- ensure .env is gitignored --------------------------------------
    gitignore_path = safe_project_file(root, root / ".gitignore", label=".gitignore")
    if gitignore_path.exists():
        gi_text = gitignore_path.read_text(encoding="utf-8")
        existing_lines = {ln.strip() for ln in gi_text.splitlines()}
        if ".env" not in existing_lines:
            if not gi_text.endswith("\n"):
                gi_text += "\n"
            gi_text += ".env\n"
            gitignore_path.write_text(gi_text, encoding="utf-8")
    else:
        gitignore_path.write_text(".env\n", encoding="utf-8")

    return key, "minted"


def key_id(key: str) -> str:
    """A non-secret short identifier: first 8 hex chars of ``sha256(key)``.

    Lets two bundles signed with different keys be distinguished without
    revealing the key itself.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:8]
