# src/wardline/core/attest_key.py
"""Attest signing-key mint and load.  The secret lives in ``.env`` (conventionally
gitignored) and is never written into any committed file under ``.wardline/``.
Mirrors the discipline of :mod:`wardline.loomweave.config.load_loomweave_token`.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from contextlib import suppress
from pathlib import Path

from wardline.core.safe_paths import safe_project_file

WARDLINE_ATTEST_KEY_ENV = "WARDLINE_ATTEST_KEY"


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

    Idempotent: a second call with the same root returns ``"present"`` without
    duplicating the entry.
    """
    existing = load_attest_key(root)
    if existing:
        return existing, "present"

    key = secrets.token_hex(32)

    # --- write to .env --------------------------------------------------
    env_path = safe_project_file(root, root / ".env", label=".env")
    if env_path.exists():
        text = env_path.read_text(encoding="utf-8")
        if not text.endswith("\n"):
            text += "\n"
        text += f'{WARDLINE_ATTEST_KEY_ENV}="{key}"\n'
    else:
        text = f'{WARDLINE_ATTEST_KEY_ENV}="{key}"\n'
    env_path.write_text(text, encoding="utf-8")
    with suppress(OSError):
        os.chmod(env_path, 0o600)

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
