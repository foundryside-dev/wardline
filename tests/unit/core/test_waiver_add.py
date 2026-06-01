from datetime import date
from pathlib import Path

import pytest

from wardline.core.config import load
from wardline.core.errors import ConfigError
from wardline.core.waivers import add_waiver, parse_waivers

FP = "a" * 64


def test_add_waiver_creates_config_and_roundtrips(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    w = add_waiver(cfg_path, fingerprint=FP, reason="false positive: validated upstream", expires=date(2026, 12, 31))
    assert w.fingerprint == FP
    waivers = parse_waivers(load(cfg_path).waivers)
    assert any(x.fingerprint == FP and x.expires == date(2026, 12, 31) for x in waivers)


def test_add_waiver_appends_to_existing(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    cfg_path.write_text("source_roots: [src]\n", encoding="utf-8")
    add_waiver(cfg_path, fingerprint=FP, reason="ok", expires=date(2026, 12, 31))
    assert load(cfg_path).source_roots == ("src",)
    assert len(load(cfg_path).waivers) == 1


def test_add_waiver_requires_reason(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    with pytest.raises(ConfigError):
        add_waiver(cfg_path, fingerprint=FP, reason="  ", expires=None)
    assert not cfg_path.exists()  # validation precedes any write


def test_add_waiver_rejects_bad_fingerprint(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    with pytest.raises(ConfigError):
        add_waiver(cfg_path, fingerprint="short", reason="ok", expires=None)
    assert not cfg_path.exists()  # validation precedes any write


def test_add_waiver_rejects_duplicate_fingerprint(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    add_waiver(cfg_path, fingerprint=FP, reason="ok", expires=None)
    with pytest.raises(ConfigError):
        add_waiver(cfg_path, fingerprint=FP, reason="ok again", expires=None)
    # File left unmutated on the rejected second add — still exactly one waiver.
    assert len(load(cfg_path).waivers) == 1


def test_add_waiver_wraps_malformed_existing_config(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    cfg_path.write_text("source_roots: [src\n", encoding="utf-8")  # unterminated flow
    with pytest.raises(ConfigError):
        add_waiver(cfg_path, fingerprint=FP, reason="ok", expires=None)
    # File left unmutated on the malformed-YAML rejection.
    assert cfg_path.read_text(encoding="utf-8") == "source_roots: [src\n"


def test_add_waiver_rejects_non_list_waivers(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    cfg_path.write_text("waivers: foo\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        add_waiver(cfg_path, fingerprint=FP, reason="ok", expires=None)
    # Corrupt non-list waivers is never silently coerced + written back.
    assert cfg_path.read_text(encoding="utf-8") == "waivers: foo\n"


def test_add_waiver_no_expiry_omits_field(tmp_path: Path) -> None:
    cfg_path = tmp_path / "wardline.yaml"
    w = add_waiver(cfg_path, fingerprint=FP, reason="ok", expires=None)
    assert w.expires is None
    waivers = parse_waivers(load(cfg_path).waivers)
    assert waivers[0].expires is None
