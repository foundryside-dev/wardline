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

from pathlib import Path

WEFT_MEMBER = "wardline"
WEFT_CONFIG_FILE = "weft.toml"
_WEFT_DIR = ".weft"


def weft_config_path(root: Path) -> Path:
    """Path to the shared operator-authored ``weft.toml`` (read-only for us)."""
    return root / WEFT_CONFIG_FILE


def weft_state_dir(root: Path) -> Path:
    """Wardline's exclusively-owned machine-state subtree."""
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
