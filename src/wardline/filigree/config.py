# src/wardline/filigree/config.py
"""Filigree bearer credential loader. Filigree's auth is opt-in bearer-token over
loopback (no HMAC); when the operator sets a token, every ``/api/weft/*`` call needs
``Authorization: Bearer <token>``. Like the Loomweave secret, the token comes from
env / ``.env`` ONLY, never from wardline.yaml — the same discipline as the OpenRouter
judge key. The env var name is Wardline's own; only the token VALUE must match what the
Filigree operator configured.
"""

from __future__ import annotations

import os
from pathlib import Path

WARDLINE_FILIGREE_TOKEN_ENV = "WARDLINE_FILIGREE_TOKEN"


def load_filigree_token(root: Path) -> str | None:
    """Return the bearer token from the environment, or a single KEY=VALUE line in
    ``root/.env``, or None. An already-set environment value always wins."""
    value = os.environ.get(WARDLINE_FILIGREE_TOKEN_ENV)
    if value:
        return value
    env_path = root / ".env"
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{WARDLINE_FILIGREE_TOKEN_ENV}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None
