"""wardline.yaml loader. Uses the `scanner` extra (pyyaml)."""

from __future__ import annotations

import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wardline.core.errors import ConfigError

_KNOWN_KEYS = frozenset(
    {"source_roots", "exclude", "rules", "baseline", "judge", "filigree", "clarion"}
)


@dataclass(frozen=True, slots=True)
class WardlineConfig:
    source_roots: tuple[str, ...] = (".",)
    exclude: tuple[str, ...] = ()
    rules_enable: tuple[str, ...] = ("*",)
    rules_severity: Mapping[str, str] = field(default_factory=dict)
    # reserved (declared so the shape is visible; inert in SP0)
    baseline: Mapping[str, Any] = field(default_factory=dict)
    judge: Mapping[str, Any] = field(default_factory=dict)
    filigree: Mapping[str, Any] = field(default_factory=dict)
    clarion: Mapping[str, Any] = field(default_factory=dict)


def load(path: Path | None) -> WardlineConfig:
    if path is None or not path.exists():
        return WardlineConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path.name} must be a mapping at top level")
    for key in raw:
        if key not in _KNOWN_KEYS:
            warnings.warn(f"unknown wardline.yaml key: {key!r}", stacklevel=2)
    rules = raw.get("rules") or {}
    return WardlineConfig(
        source_roots=tuple(raw.get("source_roots") or (".",)),
        exclude=tuple(raw.get("exclude") or ()),
        rules_enable=tuple(rules.get("enable") or ("*",)),
        rules_severity=dict(rules.get("severity") or {}),
        baseline=dict(raw.get("baseline") or {}),
        judge=dict(raw.get("judge") or {}),
        filigree=dict(raw.get("filigree") or {}),
        clarion=dict(raw.get("clarion") or {}),
    )
