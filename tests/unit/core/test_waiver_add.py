from datetime import date
from pathlib import Path

import pytest

from wardline.core.errors import ConfigError, WardlineError
from wardline.core.paths import waivers_path
from wardline.core.waivers import add_waiver, load_project_waivers

FP = "a" * 64


def test_add_waiver_creates_config_and_roundtrips(tmp_path: Path) -> None:
    w = add_waiver(
        waivers_path(tmp_path),
        fingerprint=FP,
        reason="false positive: validated upstream",
        expires=date(2026, 12, 31),
        root=tmp_path,
    )
    assert w.fingerprint == FP
    assert waivers_path(tmp_path).is_file()
    waivers = load_project_waivers(tmp_path)
    assert any(x.fingerprint == FP and x.expires == date(2026, 12, 31) for x in waivers)


def test_add_waiver_appends_to_existing(tmp_path: Path) -> None:
    other_fp = "b" * 64
    add_waiver(waivers_path(tmp_path), fingerprint=other_fp, reason="prior", expires=None, root=tmp_path)
    add_waiver(waivers_path(tmp_path), fingerprint=FP, reason="ok", expires=date(2026, 12, 31), root=tmp_path)
    waivers = load_project_waivers(tmp_path)
    assert {w.fingerprint for w in waivers} == {other_fp, FP}
    assert len(waivers) == 2


def test_add_waiver_requires_reason(tmp_path: Path) -> None:
    wp = waivers_path(tmp_path)
    with pytest.raises(ConfigError):
        add_waiver(wp, fingerprint=FP, reason="  ", expires=None, root=tmp_path)
    assert not wp.exists()  # validation precedes any write


def test_add_waiver_rejects_bad_fingerprint(tmp_path: Path) -> None:
    wp = waivers_path(tmp_path)
    with pytest.raises(ConfigError):
        add_waiver(wp, fingerprint="short", reason="ok", expires=None, root=tmp_path)
    assert not wp.exists()  # validation precedes any write


def test_add_waiver_rejects_duplicate_fingerprint(tmp_path: Path) -> None:
    add_waiver(waivers_path(tmp_path), fingerprint=FP, reason="ok", expires=None, root=tmp_path)
    with pytest.raises(ConfigError):
        add_waiver(waivers_path(tmp_path), fingerprint=FP, reason="ok again", expires=None, root=tmp_path)
    # File left unmutated on the rejected second add — still exactly one waiver.
    assert len(load_project_waivers(tmp_path)) == 1


def test_add_waiver_wraps_malformed_existing_config(tmp_path: Path) -> None:
    wp = waivers_path(tmp_path)
    wp.parent.mkdir(parents=True, exist_ok=True)
    wp.write_text("waivers: [src\n", encoding="utf-8")  # unterminated flow
    with pytest.raises(ConfigError):
        add_waiver(wp, fingerprint=FP, reason="ok", expires=None, root=tmp_path)
    # File left unmutated on the malformed-YAML rejection.
    assert wp.read_text(encoding="utf-8") == "waivers: [src\n"


def test_add_waiver_rejects_non_list_waivers(tmp_path: Path) -> None:
    wp = waivers_path(tmp_path)
    wp.parent.mkdir(parents=True, exist_ok=True)
    wp.write_text("waivers: foo\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        add_waiver(wp, fingerprint=FP, reason="ok", expires=None, root=tmp_path)
    # Corrupt non-list waivers is never silently coerced + written back.
    assert wp.read_text(encoding="utf-8") == "waivers: foo\n"


def test_add_waiver_no_expiry_omits_field(tmp_path: Path) -> None:
    w = add_waiver(waivers_path(tmp_path), fingerprint=FP, reason="ok", expires=None, root=tmp_path)
    assert w.expires is None
    waivers = load_project_waivers(tmp_path)
    assert waivers[0].expires is None


def test_add_waiver_persists_entity_binding_and_roundtrips(tmp_path: Path) -> None:
    w = add_waiver(
        waivers_path(tmp_path),
        fingerprint=FP,
        reason="false positive: validated upstream",
        expires=None,
        root=tmp_path,
        entity_sei="loomweave:eid:abc",
        entity_locator="python:function:pkg.mod.leaky",
    )
    assert w.entity_sei == "loomweave:eid:abc"
    assert w.entity_locator == "python:function:pkg.mod.leaky"
    (loaded,) = load_project_waivers(tmp_path)
    assert loaded.entity_sei == "loomweave:eid:abc"
    assert loaded.entity_locator == "python:function:pkg.mod.leaky"


def test_add_waiver_without_entity_binding_omits_fields(tmp_path: Path) -> None:
    add_waiver(waivers_path(tmp_path), fingerprint=FP, reason="ok", expires=None, root=tmp_path)
    raw = waivers_path(tmp_path).read_text(encoding="utf-8")
    assert "entity_sei" not in raw and "entity_locator" not in raw
    (loaded,) = load_project_waivers(tmp_path)
    assert loaded.entity_sei is None and loaded.entity_locator is None


def test_load_waivers_rejects_malformed_entity_sei(tmp_path: Path) -> None:
    from wardline.core.finding import FINGERPRINT_SCHEME

    wp = waivers_path(tmp_path)
    wp.parent.mkdir(parents=True, exist_ok=True)
    wp.write_text(
        f"fingerprint_scheme: {FINGERPRINT_SCHEME}\nversion: 1\n"
        f"waivers:\n- fingerprint: {FP}\n  reason: ok\n  entity_sei: 123\n",
        encoding="utf-8",
    )
    # A non-string entity_sei is a corrupt binding; it must fail loud, never drop silently.
    with pytest.raises(ConfigError, match="entity_sei"):
        load_project_waivers(tmp_path)


def test_add_waiver_refuses_direct_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    link = tmp_path / "waivers.yaml"
    link.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        add_waiver(link, fingerprint=FP, reason="ok", expires=None)

    assert outside.read_text(encoding="utf-8") == ""


def test_add_waiver_refuses_rooted_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    wp = waivers_path(tmp_path)
    wp.parent.mkdir(parents=True)
    wp.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        add_waiver(wp, fingerprint=FP, reason="ok", expires=None, root=tmp_path)

    assert outside.read_text(encoding="utf-8") == ""
