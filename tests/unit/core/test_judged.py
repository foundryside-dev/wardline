from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from wardline.core.errors import ConfigError
from wardline.core.judged import JudgedFP, load_judged, write_judged


def _fp(**kw: object) -> JudgedFP:
    base: dict[str, object] = dict(
        fingerprint="a" * 64, rule_id="PY-WL-101", path="src/m.py", message="m",
        rationale="constructor over-taint floor", model_id="anthropic/claude-opus-4-8",
        confidence=0.9, recorded_at=datetime(2026, 5, 30, tzinfo=UTC), policy_hash="sha256:abc",
    )
    base.update(kw)
    return JudgedFP(**base)  # type: ignore[arg-type]


def test_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / ".wardline" / "judged.yaml"
    write_judged(path, [_fp()])
    loaded = load_judged(path)
    match = loaded.match("a" * 64)
    assert match is not None and match.rationale == "constructor over-taint floor"
    assert loaded.match("b" * 64) is None


def test_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_judged(tmp_path / "nope.yaml").match("a" * 64) is None


def test_write_is_rule_then_fingerprint_sorted(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    # same rule_id -> tiebreak is fingerprint
    write_judged(path, [_fp(fingerprint="b" * 64), _fp(fingerprint="a" * 64)])
    doc = yaml.safe_load(path.read_text())
    assert [e["fingerprint"] for e in doc["findings"]] == ["a" * 64, "b" * 64]


def test_malformed_version_raises(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text("version: 999\nfindings: []\n")
    with pytest.raises(ConfigError):
        load_judged(path)


def test_bad_fingerprint_raises(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text("version: 1\nfindings:\n  - fingerprint: short\n    rationale: x\n")
    with pytest.raises(ConfigError):
        load_judged(path)


def test_rejudge_updates_existing_record(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    write_judged(path, [_fp(rationale="first")])
    write_judged(path, [_fp(rationale="second")])  # same fingerprint, new verdict
    match = load_judged(path).match("a" * 64)
    assert match is not None and match.rationale == "second"


def test_missing_provenance_raises(tmp_path: Path) -> None:
    # model_id / policy_hash / confidence are the audit primitive — never defaulted.
    path = tmp_path / "judged.yaml"
    path.write_text(
        "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    rationale: x\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_judged(path)


def test_out_of_range_confidence_raises(tmp_path: Path) -> None:
    path = tmp_path / "judged.yaml"
    path.write_text(
        "version: 1\nfindings:\n"
        f"  - fingerprint: {'a' * 64}\n    rationale: x\n    model_id: m\n"
        "    policy_hash: sha256:x\n    confidence: 1.5\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_judged(path)
