from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from wardline.core.baseline import (
    BASELINE_VERSION,
    build_baseline_document,
    load_baseline,
    write_baseline,
)
from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Kind, Location, Severity

_FP_A = "a" * 64
_FP_B = "b" * 64


def _finding(fp: str, *, rule: str = "PY-WL-101", sev: Severity = Severity.ERROR, path: str = "src/m.py") -> Finding:
    return Finding(
        rule_id=rule, message=f"msg {fp[:4]}", severity=sev, kind=Kind.DEFECT,
        location=Location(path=path, line_start=1), fingerprint=fp,
    )


def test_build_document_shape_and_version() -> None:
    doc = build_baseline_document([_finding(_FP_A)])
    assert doc["version"] == BASELINE_VERSION
    assert doc["entries"][0]["fingerprint"] == _FP_A
    assert doc["entries"][0]["rule_id"] == "PY-WL-101"
    assert "path" in doc["entries"][0] and "message" in doc["entries"][0]


def test_build_document_dedups_and_sorts_severity_first() -> None:
    findings = [
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),
        _finding(_FP_B, sev=Severity.CRITICAL, rule="PY-WL-101"),
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),  # dup fingerprint
    ]
    entries = build_baseline_document(findings)["entries"]
    assert [e["fingerprint"] for e in entries] == [_FP_B, _FP_A]  # CRITICAL first; dup collapsed


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    p = tmp_path / ".wardline" / "baseline.yaml"
    write_baseline(p, [_finding(_FP_A), _finding(_FP_B)])
    bl = load_baseline(p)
    assert bl.fingerprints == frozenset({_FP_A, _FP_B})
    assert bl.contains(_FP_A) and not bl.contains("c" * 64)


def test_missing_file_is_empty_baseline(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope.yaml").fingerprints == frozenset()


def test_empty_file_is_empty_baseline(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("", encoding="utf-8")
    assert load_baseline(p).fingerprints == frozenset()


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("entries: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_version_mismatch_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"version": 999, "entries": []}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_bad_fingerprint_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"version": BASELINE_VERSION, "entries": [{"fingerprint": "short"}]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_duplicate_fingerprint_in_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump({"version": BASELINE_VERSION, "entries": [{"fingerprint": _FP_A}, {"fingerprint": _FP_A}]}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_baseline(p)
