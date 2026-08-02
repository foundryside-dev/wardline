# src/wardline/core/judged.py
"""Machine-managed judged-FALSE_POSITIVE records (SP5).

``.weft/wardline/judged.yaml`` is the SP3 baseline pattern applied to LLM-judge output:
a committed, human-readable, provenance-carrying snapshot of findings the triage
judge ruled FALSE_POSITIVE. Keyed on the full ``Finding.fingerprint`` (strict
match). Hand-authored waivers live in ``.weft/wardline/waivers.yaml``; these are machine-written.
No governance — the model's verbatim rationale is the audit primitive.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wardline.core.errors import ConfigError
from wardline.core.finding import FINGERPRINT_SCHEME, require_fingerprint_scheme
from wardline.core.judge_types import CONCRETE_JUDGE_TRANSPORTS, JudgeTransport
from wardline.core.optional_deps import require_yaml
from wardline.core.safe_paths import safe_project_file

JUDGED_VERSION: int = 2
_SUPPORTED_JUDGED_VERSIONS = frozenset({1, JUDGED_VERSION})
_HEX = frozenset("0123456789abcdef")


def _require_typed_concrete_transport(value: object) -> JudgeTransport:
    if not isinstance(value, JudgeTransport):
        raise TypeError("judge_transport must be a JudgeTransport")
    if value not in CONCRETE_JUDGE_TRANSPORTS:
        raise ValueError("judge_transport must be concrete")
    return value


@dataclass(frozen=True, slots=True)
class JudgedFP:
    fingerprint: str
    rule_id: str
    path: str
    message: str
    rationale: str
    model_id: str
    judge_transport: JudgeTransport
    confidence: float
    recorded_at: datetime
    policy_hash: str

    def __post_init__(self) -> None:
        _require_typed_concrete_transport(self.judge_transport)


class JudgedSet:
    def __init__(self, entries: Iterable[JudgedFP]) -> None:
        self._by_fp: dict[str, JudgedFP] = {e.fingerprint: e for e in entries}

    def match(self, fingerprint: str) -> JudgedFP | None:
        return self._by_fp.get(fingerprint)

    def fingerprints(self) -> frozenset[str]:
        return frozenset(self._by_fp)


def build_judged_document(entries: Iterable[JudgedFP]) -> dict[str, Any]:
    unique: dict[str, JudgedFP] = {}
    for e in entries:
        _require_typed_concrete_transport(e.judge_transport)
        unique[e.fingerprint] = e  # last write wins (re-judge updates)
    ordered = sorted(unique.values(), key=lambda e: (e.rule_id, e.fingerprint))
    return {
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "version": JUDGED_VERSION,
        "findings": [
            {
                "fingerprint": e.fingerprint,
                "rule_id": e.rule_id,
                "path": e.path,
                "message": e.message,
                "verdict": "FALSE_POSITIVE",
                "rationale": e.rationale,
                "confidence": e.confidence,
                "model_id": e.model_id,
                "judge_transport": e.judge_transport.value,
                "recorded_at": e.recorded_at.isoformat(),
                "policy_hash": e.policy_hash,
            }
            for e in ordered
        ],
    }


def write_judged(path: Path, entries: Iterable[JudgedFP], root: Path | None = None) -> None:
    yaml = require_yaml("writing judged.yaml")
    if root is not None:
        path = safe_project_file(root, path, label=path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(build_judged_document(entries), sort_keys=False, default_flow_style=False, allow_unicode=True)
    path.write_text(text, encoding="utf-8")


def load_judged(path: Path) -> JudgedSet:
    if not path.exists():
        return JudgedSet([])
    yaml = require_yaml("loading judged.yaml")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if raw is None:
        return JudgedSet([])
    return validate_judged_document(
        raw,
        store_name=path.name,
        require_current_scheme=True,
        allow_empty=True,
    )


def validate_judged_document(
    raw: object,
    *,
    store_name: str,
    require_current_scheme: bool,
    allow_empty: bool,
) -> JudgedSet:
    """Validate and parse one already-decoded judged document without mutating it."""
    if not isinstance(raw, dict):
        raise ConfigError(f"{store_name}: must be a mapping at top level")
    if not raw and allow_empty:
        return JudgedSet([])
    # Loader order is load-bearing: empty-guard (above) → scheme → version.
    if require_current_scheme:
        require_fingerprint_scheme(raw, store_name=store_name)
    version = raw.get("version")
    if type(version) is not int or version not in _SUPPORTED_JUDGED_VERSIONS:
        raise ConfigError(f"{store_name}: version must be exactly 1 or {JUDGED_VERSION}, got {version!r}")
    findings = raw.get("findings", [])
    if not isinstance(findings, list):
        raise ConfigError(f"{store_name}: 'findings' must be a list")
    entries: list[JudgedFP] = []
    seen: set[str] = set()
    for idx, e in enumerate(findings):
        if not isinstance(e, dict):
            raise ConfigError(f"{store_name} findings[{idx}] must be a mapping")
        fp = e.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"{store_name} findings[{idx}].fingerprint must be a 64-char lowercase hex string")
        if fp in seen:
            raise ConfigError(f"{store_name} findings[{idx}]: duplicate fingerprint {fp!r}")
        seen.add(fp)
        # A judged record suppresses a finding ONLY as a FALSE_POSITIVE verdict. Require
        # the field and reject any other value so a hand-edited TRUE_POSITIVE (or a
        # missing verdict) cannot be smuggled in as a silent suppression. write_judged
        # always emits verdict: FALSE_POSITIVE, so machine round-trips stay valid.
        verdict = _require_str(e, "verdict", idx, store_name)
        if verdict != "FALSE_POSITIVE":
            raise ConfigError(f"{store_name} findings[{idx}].verdict must be FALSE_POSITIVE, got {verdict!r}")
        rationale = _require_str(e, "rationale", idx, store_name)
        # Provenance is the audit primitive — never default it. A judged record with
        # no attributable model / policy / confidence is an unauditable suppression.
        model_id = _require_str(e, "model_id", idx, store_name)
        judge_transport = JudgeTransport.OPENROUTER if version == 1 else _require_concrete_transport(e, idx, store_name)
        policy_hash = _require_str(e, "policy_hash", idx, store_name)
        confidence = _require_confidence(e, idx, store_name)
        recorded_at = _parse_dt(e.get("recorded_at"), idx, store_name)
        entries.append(
            JudgedFP(
                fingerprint=fp,
                rule_id=str(e.get("rule_id", "")),
                path=str(e.get("path", "")),
                message=str(e.get("message", "")),
                rationale=rationale,
                model_id=model_id,
                judge_transport=judge_transport,
                confidence=confidence,
                recorded_at=recorded_at,
                policy_hash=policy_hash,
            )
        )
    return JudgedSet(entries)


def _require_concrete_transport(entry: dict[str, Any], idx: int, name: str) -> JudgeTransport:
    value = entry.get("judge_transport")
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{name} findings[{idx}].judge_transport must be a concrete transport string")
    try:
        transport = JudgeTransport(value)
    except ValueError:
        raise ConfigError(f"{name} findings[{idx}].judge_transport must be codex-cli or openrouter") from None
    if transport not in CONCRETE_JUDGE_TRANSPORTS:
        raise ConfigError(f"{name} findings[{idx}].judge_transport must be codex-cli or openrouter")
    return transport


def _require_str(entry: dict[str, Any], key: str, idx: int, name: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} findings[{idx}].{key} is required (non-empty string)")
    return value


def _require_confidence(entry: dict[str, Any], idx: int, name: str) -> float:
    value = entry.get("confidence")
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{name} findings[{idx}].confidence must be a number, got {value!r}")
    confidence = float(value)
    if not 0.0 <= confidence <= 1.0:
        raise ConfigError(f"{name} findings[{idx}].confidence must be 0.0..1.0, got {confidence!r}")
    return confidence


def _parse_dt(raw: Any, idx: int, name: str) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, str):
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ConfigError(f"{name} findings[{idx}].recorded_at is not ISO: {raw!r}") from exc
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    raise ConfigError(f"{name} findings[{idx}].recorded_at must be an ISO datetime string")
