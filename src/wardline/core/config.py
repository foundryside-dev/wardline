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
    {"source_roots", "exclude", "rules", "baseline", "waivers", "judge", "filigree", "clarion"}
)


@dataclass(frozen=True, slots=True)
class WardlineConfig:
    source_roots: tuple[str, ...] = (".",)
    exclude: tuple[str, ...] = ()
    rules_enable: tuple[str, ...] = ("*",)
    rules_severity: Mapping[str, str] = field(default_factory=dict)
    # reserved (declared so the shape is visible; inert in SP0)
    baseline: Mapping[str, Any] = field(default_factory=dict)
    waivers: tuple[Mapping[str, Any], ...] = ()
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
        waivers=tuple(raw.get("waivers") or ()),
        judge=dict(raw.get("judge") or {}),
        filigree=dict(raw.get("filigree") or {}),
        clarion=dict(raw.get("clarion") or {}),
    )


@dataclass(frozen=True, slots=True)
class JudgeSettings:
    model: str = "anthropic/claude-opus-4-8"
    context_lines: int = 30
    max_findings: int | None = None
    policy_file: str | None = None


def parse_judge_settings(raw: Mapping[str, Any]) -> JudgeSettings:
    """Parse the ``judge:`` config section, fail-loud on bad types."""

    def _int(key: str, default: int | None) -> int | None:
        if key not in raw or raw[key] is None:
            return default
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"judge.{key} must be an integer, got {type(value).__name__}")
        return value

    def _str(key: str, default: str | None) -> str | None:
        if key not in raw or raw[key] is None:
            return default
        value = raw[key]
        if not isinstance(value, str):
            raise ConfigError(f"judge.{key} must be a string, got {type(value).__name__}")
        return value

    model = _str("model", "anthropic/claude-opus-4-8")
    assert model is not None  # default is non-None
    ctx = _int("context_lines", 30)
    assert ctx is not None
    return JudgeSettings(
        model=model,
        context_lines=ctx,
        max_findings=_int("max_findings", None),
        policy_file=_str("policy_file", None),
    )
