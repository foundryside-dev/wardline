# src/wardline/clarion/config.py
"""SP9 credentials + project guard. The HMAC secret comes from env / `.env` ONLY,
never from wardline.yaml — the same discipline as the OpenRouter judge key. The
env var name is independent of Clarion's server-side name; only the secret VALUE
must match the value the Clarion operator put in `serve.http.identity_token_env`.
"""

from __future__ import annotations

import os
from pathlib import Path

WARDLINE_CLARION_TOKEN_ENV = "WARDLINE_CLARION_TOKEN"


def load_clarion_token(root: Path) -> str | None:
    """Return the HMAC secret from the environment, or a single KEY=VALUE line in
    ``root/.env``, or None. An already-set environment value always wins."""
    value = os.environ.get(WARDLINE_CLARION_TOKEN_ENV)
    if value:
        return value
    env_path = root / ".env"
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{WARDLINE_CLARION_TOKEN_ENV}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def resolve_project_name(root: Path) -> str:
    """Clarion's project guard handle: the project-root directory name."""
    return root.resolve().name
