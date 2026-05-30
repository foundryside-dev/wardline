"""wardline.yaml loader. Uses the `scanner` extra (pyyaml + jsonschema)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.errors import ConfigError


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
    try:
        jsonschema.validate(raw, WARDLINE_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"invalid {path.name}: {exc.message}") from exc
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
    # FALSE_POSITIVE verdicts below this confidence are reported but NOT written to
    # judged.yaml (the conservative prior: don't suppress a real defect on a low-
    # confidence guess). Set to 0.0 to write every FP.
    write_confidence_floor: float = 0.5


def parse_judge_settings(raw: Mapping[str, Any]) -> JudgeSettings:
    """Parse the ``judge:`` config section, fail-loud on bad types.

    ``wardline.yaml`` (including ``judge.policy_file``) is TRUSTED operator input —
    the same tier as ``rules.enable`` (which can already disable every rule). Scanned
    source code is the untrusted tier; the two are kept distinct in the judge prompt.
    """

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
    if ctx < 0:
        raise ConfigError(f"judge.context_lines must be >= 0, got {ctx}")
    max_findings = _int("max_findings", None)
    if max_findings is not None and max_findings <= 0:
        raise ConfigError(f"judge.max_findings must be a positive integer, got {max_findings}")
    floor = raw.get("write_confidence_floor")
    if floor is None:
        floor_val = 0.5
    elif isinstance(floor, bool) or not isinstance(floor, int | float):
        raise ConfigError(f"judge.write_confidence_floor must be a number, got {type(floor).__name__}")
    else:
        floor_val = float(floor)
        if not 0.0 <= floor_val <= 1.0:
            raise ConfigError(f"judge.write_confidence_floor must be 0.0..1.0, got {floor_val}")
    return JudgeSettings(
        model=model,
        context_lines=ctx,
        max_findings=max_findings,
        policy_file=_str("policy_file", None),
        write_confidence_floor=floor_val,
    )
