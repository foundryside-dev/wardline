# src/wardline/core/paths.py
"""Single source of truth for Weft federation on-disk locations.

Two surfaces, two owners (Weft config/store consolidation convention):

* ``weft.toml`` (project root) — OPERATOR-authored, read-only for wardline. We
  read our ``[wardline]`` table; we NEVER write this file.
* ``.weft/wardline/`` (project root) — machine-written state owned exclusively by
  wardline (``baseline.yaml``, ``judged.yaml``, ``waivers.yaml``). We are the sole
  writer of this subtree and never read or write a sibling's subtree.

Sibling runtime state lives under ``.weft/<sibling>/`` (preferred) with a
transition-window fallback to the legacy ``.{sibling}/`` dot-dir.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

WEFT_MEMBER = "wardline"
WEFT_CONFIG_FILE = "weft.toml"
_WEFT_DIR = ".weft"


def weft_config_path(root: Path) -> Path:
    """Path to the shared operator-authored ``weft.toml`` (read-only for us)."""
    return root / WEFT_CONFIG_FILE


def _store_dir_override(root: Path) -> str | None:
    """Read the operator's ``[wardline].store_dir`` override from weft.toml, or None.

    Read defensively and silently (C-9c): a missing/malformed weft.toml, a non-table
    ``[wardline]``, or a non-string ``store_dir`` all fall through to None so the
    default location is used. This never raises — store-dir resolution must not be
    load-bearing on the shared file parsing cleanly."""
    try:
        parsed = tomllib.loads(weft_config_path(root).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    table = parsed.get("wardline")
    if not isinstance(table, dict):
        return None
    value = table.get("store_dir")
    return value if isinstance(value, str) and value.strip() else None


def weft_state_dir(root: Path) -> Path:
    """Wardline's exclusively-owned machine-state subtree.

    Honors an operator ``[wardline].store_dir`` override in weft.toml (canonical key,
    legis reference): a relative override resolves under ``root``, an absolute one is
    used verbatim. Defaults to ``root/.weft/wardline``."""
    override = _store_dir_override(root)
    if override is not None:
        candidate = Path(override)
        return candidate if candidate.is_absolute() else root / candidate
    return root / _WEFT_DIR / WEFT_MEMBER


def baseline_path(root: Path) -> Path:
    return weft_state_dir(root) / "baseline.yaml"


def judged_path(root: Path) -> Path:
    return weft_state_dir(root) / "judged.yaml"


def waivers_path(root: Path) -> Path:
    return weft_state_dir(root) / "waivers.yaml"


def sibling_state_dir(root: Path, sibling: str) -> Path:
    """Preferred location of a sibling member's runtime subtree."""
    return root / _WEFT_DIR / sibling


def legacy_sibling_dir(root: Path, sibling: str) -> Path:
    """Legacy pre-consolidation dot-dir for a sibling (transition-window fallback)."""
    return root / f".{sibling}"
