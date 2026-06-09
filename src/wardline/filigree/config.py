# src/wardline/filigree/config.py
"""Filigree bearer credential loader. Filigree's auth is opt-in bearer-token over
loopback (no HMAC); when a token is in play, every ``/api/weft/*`` call needs
``Authorization: Bearer <token>``. Only the token VALUE must match what the Filigree
daemon expects.

This mirrors filigree's OWN inbound resolver (``filigree/federation_token.py``) so the
outbound (client) token wardline emits matches the daemon's with zero operator
ceremony on a same-host install. Resolution order (highest precedence first):

  1. env ``WEFT_FEDERATION_TOKEN``                         — operator override / cross-host
  2. ``root/.env`` ``WEFT_FEDERATION_TOKEN``               — wardline's portable convention
  3. ``<root>/.weft/filigree/federation_token``            — filigree's auto-minted 0600 file
  4. legacy ``WARDLINE_FILIGREE_TOKEN`` (env then .env)    — deprecated transition fallback
  5. None                                                  — auth stays off

Rung 3 is the same project-store file filigree mints and validates against (the C-9e
same-host cross-member read; conventions.md C-3 + conflict-register §A-15): reading it
makes the client token match the per-project daemon with no env/.env/.mcp.json config.
This token is loopback deconfliction/identification plumbing, **not** a secret — the
0600 mode is filigree's to set; wardline only reads. The env-sourced tokens (rungs 1/4)
otherwise come from env / ``.env`` ONLY, never from weft.toml — the same discipline as
the Loomweave secret and the OpenRouter judge key.
"""

from __future__ import annotations

import os
from pathlib import Path

from wardline.core.safe_paths import safe_project_file

WEFT_FEDERATION_TOKEN_ENV = "WEFT_FEDERATION_TOKEN"
# Deprecated fallback — read after the federation-scoped name so existing
# deployments (e.g. lacuna's .env) keep working until they migrate.
WARDLINE_FILIGREE_TOKEN_ENV = "WARDLINE_FILIGREE_TOKEN"

# Filigree's auto-minted token, relative to the project root. Mirrors filigree's
# single-project store_dir (``.weft/filigree/``) and the filename it persists
# (``federation_token``); kept in lockstep with filigree/federation_token.py.
_FILIGREE_MINT_RELPATH = (".weft", "filigree", "federation_token")


def _read_token(name: str, root: Path) -> str | None:
    """Return the value of ``name`` from the environment, or from a single
    ``KEY=VALUE`` line in ``root/.env``, or None. An already-set environment value
    always wins over the file."""
    value = os.environ.get(name)
    if value:
        return value
    env_path = safe_project_file(root, root / ".env", label=".env")
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{name}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def _read_filigree_mint(root: Path) -> str | None:
    """Tier 3: filigree's auto-minted federation token under the project store
    (``<root>/.weft/filigree/federation_token``), stripped, or None.

    Strictly read-only — wardline never mints this file (filigree does, at daemon
    boot / install / doctor). Missing or unreadable falls through cleanly to None so
    the emit path degrades to the legacy/off rungs rather than crashing the scan.
    """
    path = safe_project_file(root, root.joinpath(*_FILIGREE_MINT_RELPATH), label="federation_token")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def load_filigree_token(root: Path) -> str | None:
    """Resolve the outbound Filigree bearer token (see the module docstring for the
    five-rung order), or None when federation auth is off."""
    # Rungs 1-2: the canonical federation name, resolved fully (env then .env).
    value = _read_token(WEFT_FEDERATION_TOKEN_ENV, root)
    if value:
        return value
    # Rung 3: filigree's auto-minted project-store token (same-host, zero-ceremony).
    value = _read_filigree_mint(root)
    if value:
        return value
    # Rung 4: the deprecated legacy name (env then .env) for un-migrated deployments.
    value = _read_token(WARDLINE_FILIGREE_TOKEN_ENV, root)
    if value:
        return value
    # Rung 5: off.
    return None
