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
    legis reference); defaults to ``root/.weft/wardline``. The override is CONFINED
    under ``root``: a relative path resolves under root, an absolute path is honored
    only if it lands inside root, and any value that resolves OUTSIDE root (an absolute
    elsewhere, or a ``..`` escape) is ignored and the default is used. This keeps
    state-dir resolution consistent with the writers, which confine through
    ``safe_project_file`` and would otherwise reject an out-of-root target at write
    time — and it denies a malicious weft.toml a write-redirect primitive (weft.toml
    is untrusted input when wardline scans an untrusted repo)."""
    override = _store_dir_override(root)
    default = root / _WEFT_DIR / WEFT_MEMBER
    if override is None:
        return default
    candidate = Path(override)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return default  # escaping override → fall back to the in-root default
    # Return the resolved form (not the pre-resolve candidate) so a ``..`` segment
    # in store_dir never leaks into the user-printed state path.
    return resolved


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
