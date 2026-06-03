# src/wardline/install/pack.py
"""`wardline install` pack activation helper."""

from __future__ import annotations

from pathlib import Path

import yaml

from wardline.core.errors import ConfigError


def activate_pack(root: Path, pack_name: str) -> str:
    """Add pack_name to the 'packs' list in wardline.yaml.

    Returns "activated" or "already_active".
    """
    config_path = root / "wardline.yaml"
    if not config_path.exists():
        raw = {"packs": [pack_name]}
        config_path.write_text(
            yaml.safe_dump(raw, sort_keys=False, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        return "activated"

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {config_path.name}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path.name} must be a mapping")

    packs = raw.get("packs")
    if packs is None:
        packs = []
        raw["packs"] = packs
    elif not isinstance(packs, list):
        raise ConfigError(f"malformed {config_path.name}: 'packs' must be a list")

    if pack_name in packs:
        return "already_active"

    new_packs = list(packs)
    new_packs.append(pack_name)
    raw["packs"] = new_packs

    config_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
    return "activated"
