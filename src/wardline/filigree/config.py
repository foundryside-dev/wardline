# src/wardline/filigree/config.py
"""Filigree bearer credential loader. Filigree's auth is opt-in bearer-token over
loopback (no HMAC); when a token is in play, every ``/api/weft/*`` call needs
``Authorization: Bearer <token>``. Only the token VALUE must match what the Filigree
daemon expects.

This mirrors filigree's OWN inbound resolver (``filigree/federation_token.py``) so the
outbound (client) token wardline emits matches the daemon's with zero operator
ceremony on a same-host install. Resolution order (highest precedence first):

  1. env ``WEFT_FEDERATION_TOKEN``                         — operator override / cross-host
  2. legacy env ``WARDLINE_FILIGREE_TOKEN``                 — deprecated operator fallback
  3. ``root/.env`` ``WEFT_FEDERATION_TOKEN``               — wardline's portable convention
  4. ``<root>/.weft/filigree/federation_token``            — filigree's auto-minted 0600 file
  5. legacy ``root/.env`` ``WARDLINE_FILIGREE_TOKEN``       — deprecated file fallback
  6. None                                                  — auth stays off

Rung 3 is the same project-store file filigree mints and validates against (the C-9e
same-host cross-member read; conventions.md C-3 + conflict-register §A-15): reading it
makes the client token match the per-project daemon with no env/.env/.mcp.json config.
This token is loopback deconfliction/identification plumbing, **not** a secret — the
0600 mode is filigree's to set; wardline only reads. The configured tokens otherwise
come from env / ``.env`` ONLY, never from weft.toml — the same discipline as
the Loomweave secret and the OpenRouter judge key.
"""

from __future__ import annotations

import os
from pathlib import Path

from wardline.core.safe_paths import safe_project_file, safe_read_text_if_regular

WEFT_FEDERATION_TOKEN_ENV = "WEFT_FEDERATION_TOKEN"
# Deprecated fallback — read after the federation-scoped name so existing
# deployments (e.g. lacuna's .env) keep working until they migrate.
WARDLINE_FILIGREE_TOKEN_ENV = "WARDLINE_FILIGREE_TOKEN"

# Filigree's auto-minted token, relative to the project root. Mirrors filigree's
# single-project store_dir (``.weft/filigree/``) and the filename it persists
# (``federation_token``); kept in lockstep with filigree/federation_token.py.
_FILIGREE_MINT_RELPATH = (".weft", "filigree", "federation_token")


def _read_env_token(name: str) -> str | None:
    """Return a non-empty process environment token, or None."""
    value = os.environ.get(name)
    return value or None


def _read_dotenv_token(name: str, root: Path) -> str | None:
    """Return ``name`` from a single ``KEY=VALUE`` line in ``root/.env``, or None."""
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
    text = safe_read_text_if_regular(root, root.joinpath(*_FILIGREE_MINT_RELPATH), label="federation_token")
    if text is None:
        return None
    value = text.strip()
    return value or None


def load_filigree_token(root: Path) -> str | None:
    """Resolve the outbound Filigree bearer token (see the module docstring for the
    six-rung order), or None when federation auth is off."""
    # Rungs 1-2: process environment is operator-controlled and outranks every
    # project-local token file, including root/.env entries with newer names.
    value = _read_env_token(WEFT_FEDERATION_TOKEN_ENV)
    if value:
        return value
    value = _read_env_token(WARDLINE_FILIGREE_TOKEN_ENV)
    if value:
        return value
    # Rung 3: the canonical federation name in root/.env.
    value = _read_dotenv_token(WEFT_FEDERATION_TOKEN_ENV, root)
    if value:
        return value
    # Rung 4: filigree's auto-minted project-store token (same-host, zero-ceremony).
    value = _read_filigree_mint(root)
    if value:
        return value
    # Rung 5: the deprecated legacy name in root/.env for un-migrated deployments.
    value = _read_dotenv_token(WARDLINE_FILIGREE_TOKEN_ENV, root)
    if value:
        return value
    # Rung 6: off.
    return None
