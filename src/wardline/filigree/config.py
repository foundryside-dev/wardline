# src/wardline/filigree/config.py
"""Filigree bearer credential loader. Filigree's auth is opt-in bearer-token over
loopback (no HMAC); when the operator sets a token, every ``/api/weft/*`` call needs
``Authorization: Bearer <token>``. Like the Loomweave secret, the token comes from
env / ``.env`` ONLY, never from wardline.yaml — the same discipline as the OpenRouter
judge key.

The credential is read from the federation-scoped ``WEFT_FEDERATION_TOKEN`` (adopted
for lockstep across the Weft federation). The legacy ``WARDLINE_FILIGREE_TOKEN`` is
still honored as a deprecated fallback so existing deployments keep working; the new
name is preferred and is what the operator-facing messages point at. Only the token
VALUE must match what the Filigree operator configured.
"""

from __future__ import annotations

import os
from pathlib import Path

WEFT_FEDERATION_TOKEN_ENV = "WEFT_FEDERATION_TOKEN"
# Deprecated fallback — read after the federation-scoped name so existing
# deployments (e.g. lacuna's .env) keep working until they migrate.
WARDLINE_FILIGREE_TOKEN_ENV = "WARDLINE_FILIGREE_TOKEN"

# Priority order: the new federation name fully (env then .env), then the legacy
# name fully. Preferring the new name everywhere is the correct deprecation behavior.
_TOKEN_ENV_NAMES = (WEFT_FEDERATION_TOKEN_ENV, WARDLINE_FILIGREE_TOKEN_ENV)


def _read_token(name: str, root: Path) -> str | None:
    """Return the value of ``name`` from the environment, or from a single
    ``KEY=VALUE`` line in ``root/.env``, or None. An already-set environment value
    always wins over the file."""
    value = os.environ.get(name)
    if value:
        return value
    env_path = root / ".env"
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{name}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def load_filigree_token(root: Path) -> str | None:
    """Return the bearer token from ``WEFT_FEDERATION_TOKEN`` (env or ``root/.env``),
    falling back to the deprecated ``WARDLINE_FILIGREE_TOKEN``, or None."""
    for name in _TOKEN_ENV_NAMES:
        value = _read_token(name, root)
        if value:
            return value
    return None
