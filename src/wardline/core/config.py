"""wardline.yaml loader. Uses the `scanner` extra (pyyaml + jsonschema)."""

from __future__ import annotations

import os
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
    packs: tuple[str, ...] = ()

    @property
    def clarion_url(self) -> str | None:
        value = self.clarion.get("url")
        return value if isinstance(value, str) else None

    @property
    def filigree_url(self) -> str | None:
        value = self.filigree.get("url")
        return value if isinstance(value, str) else None


def _deep_merge(local: dict[str, Any], default: dict[str, Any]) -> dict[str, Any]:
    res = dict(default)
    for k, v in local.items():
        if k in res and isinstance(res[k], dict) and isinstance(v, dict):
            res[k] = _deep_merge(v, res[k])
        elif k in res and isinstance(res[k], list) and isinstance(v, list):
            if k in ("exclude", "source_roots"):
                res[k] = list(dict.fromkeys(res[k] + v))
            else:
                res[k] = res[k] + v
        else:
            res[k] = v
    return res


def load(path: Path | None) -> WardlineConfig:
    if path is None or not path.exists():
        return WardlineConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path.name} must be a mapping at top level")

    # Load and merge packs config
    packs = raw.get("packs") or []
    if not isinstance(packs, list):
        raise ConfigError(f"packs key in {path.name} must be a list")

    merged_raw = dict(raw)
    for pack_name in packs:
        if not isinstance(pack_name, str):
            raise ConfigError(f"packs list in {path.name} must contain strings only")
        try:
            import importlib

            pkg = importlib.import_module(pack_name)
        except ImportError as exc:
            raise ConfigError(f"failed to load trust-grammar pack {pack_name!r}: {exc}") from exc

        pack_config = getattr(pkg, "config", None)
        if pack_config is not None:
            if not isinstance(pack_config, dict):
                raise ConfigError(f"pack {pack_name!r} attribute 'config' must be a dictionary")
            merged_raw = _deep_merge(merged_raw, pack_config)

    try:
        jsonschema.validate(merged_raw, WARDLINE_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"invalid {path.name} (after merging packs): {exc.message}") from exc

    rules = merged_raw.get("rules") or {}
    return WardlineConfig(
        source_roots=tuple(merged_raw.get("source_roots") or (".",)),
        exclude=tuple(merged_raw.get("exclude") or ()),
        rules_enable=tuple(rules.get("enable") or ("*",)),
        rules_severity=dict(rules.get("severity") or {}),
        baseline=dict(merged_raw.get("baseline") or {}),
        waivers=tuple(merged_raw.get("waivers") or ()),
        judge=dict(merged_raw.get("judge") or {}),
        filigree=dict(merged_raw.get("filigree") or {}),
        clarion=dict(merged_raw.get("clarion") or {}),
        packs=tuple(packs),
    )


_CLARION_URL_ENV = "WARDLINE_CLARION_URL"
_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _config_for(root: Path, config_path: Path | None) -> WardlineConfig:
    return load(config_path if config_path is not None else root / "wardline.yaml")


def resolve_clarion_url(flag: str | None, root: Path, config_path: Path | None = None) -> str | None:
    """Clarion URL by precedence: explicit flag > env var > wardline.yaml."""
    if flag is not None:
        return flag
    env = os.environ.get(_CLARION_URL_ENV)
    if env:
        return env
    return _config_for(root, config_path).clarion_url


def resolve_filigree_url(flag: str | None, root: Path, config_path: Path | None = None) -> str | None:
    """Filigree Loom URL by precedence: explicit flag > env var > wardline.yaml."""
    if flag is not None:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    return _config_for(root, config_path).filigree_url


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
