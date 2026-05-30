# src/wardline/core/baseline.py
"""The git-committable finding baseline (SP3).

A ``.wardline/baseline.yaml`` is a snapshot of accepted findings keyed on the
full ``Finding.fingerprint`` (strict match — see spec §2 dial 1). The committed
file carries ``rule_id``/``path``/``message`` per entry for human auditability in
a git diff; only ``fingerprint`` is loaded into the match set. No governance.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Severity

BASELINE_VERSION: int = 1
"""Bumped on a format change; validated on load (mirrors STDLIB_TAINT_VERSION)."""

# CRITICAL sorts first so high-severity entries sit at the top of the git diff.
_SEVERITY_SORT: dict[Severity, int] = {
    Severity.CRITICAL: 0, Severity.ERROR: 1, Severity.WARN: 2, Severity.INFO: 3, Severity.NONE: 4,
}
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in self.fingerprints


def build_baseline_document(findings: Iterable[Finding]) -> dict[str, Any]:
    """Pure: the YAML-shaped dict for the given findings (deduped, severity-sorted)."""
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.fingerprint, f)
    ordered = sorted(
        unique.values(),
        key=lambda f: (_SEVERITY_SORT[f.severity], f.rule_id, f.location.path, f.fingerprint),
    )
    return {
        "version": BASELINE_VERSION,
        "entries": [
            {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.location.path, "message": f.message}
            for f in ordered
        ],
    }


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        build_baseline_document(findings), sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    path.write_text(text, encoding="utf-8")


def load_baseline(path: Path) -> Baseline:
    if not path.exists():
        return Baseline(frozenset())
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    return _build_baseline(raw, path.name)


def _build_baseline(raw: Any, name: str = "baseline.yaml") -> Baseline:
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}: must be a mapping at top level")
    if not raw:
        return Baseline(frozenset())
    if raw.get("version") != BASELINE_VERSION:
        raise ConfigError(f"{name}: version mismatch — expected {BASELINE_VERSION}, got {raw.get('version')!r}")
    entries = raw.get("entries")
    if entries is None:
        return Baseline(frozenset())
    if not isinstance(entries, list):
        raise ConfigError(f"{name}: 'entries' must be a list")
    fingerprints: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"{name} entries[{idx}] must be a mapping")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"{name} entries[{idx}].fingerprint must be a 64-char lowercase hex string")
        if fp in fingerprints:
            raise ConfigError(f"{name} entries[{idx}]: duplicate fingerprint {fp!r}")
        fingerprints.add(fp)
    return Baseline(frozenset(fingerprints))
