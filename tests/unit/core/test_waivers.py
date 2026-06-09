from __future__ import annotations

from datetime import date

import pytest

from wardline.core.errors import ConfigError, SchemeMismatchError
from wardline.core.finding import FINGERPRINT_SCHEME
from wardline.core.waivers import (
    WAIVERS_VERSION,
    Waiver,
    WaiverSet,
    build_waivers_document,
    parse_waivers,
)

_FP = "a" * 64


def test_parse_minimal_waiver() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "false positive"}])
    assert w == Waiver(fingerprint=_FP, reason="false positive", expires=None)


def test_parse_expiry_from_date_object() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": date(2026, 9, 1)}])
    assert w.expires == date(2026, 9, 1)


def test_parse_expiry_from_iso_string() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "2026-09-01"}])
    assert w.expires == date(2026, 9, 1)


def test_missing_reason_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP}])
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "   "}])


def test_bad_fingerprint_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": "short", "reason": "r"}])


def test_unparseable_expiry_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "soon"}])


def test_duplicate_fingerprint_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "a"}, {"fingerprint": _FP, "reason": "b"}])


def test_match_active_when_no_expiry() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP, "reason": "r"}]))
    assert ws.match(_FP, date(2026, 5, 30)) is not None
    assert ws.match("b" * 64, date(2026, 5, 30)) is None


def test_expiry_boundary_inclusive_then_expires() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "2026-05-30"}]))
    assert ws.match(_FP, date(2026, 5, 30)) is not None  # valid THROUGH expiry day
    assert ws.match(_FP, date(2026, 5, 31)) is None  # expired the day after


def test_add_and_load_project_waivers_weft_state(tmp_path):
    from datetime import date

    from wardline.core import paths
    from wardline.core.waivers import add_waiver, load_project_waivers

    fp = "a" * 64
    add_waiver(paths.waivers_path(tmp_path), fingerprint=fp, reason="ok", expires=date(2030, 1, 1), root=tmp_path)
    assert paths.waivers_path(tmp_path).is_file()
    assert paths.weft_state_dir(tmp_path).is_dir()
    loaded = load_project_waivers(tmp_path)
    assert [w.fingerprint for w in loaded] == [fp]
    assert loaded[0].expires == date(2030, 1, 1)


def test_load_project_waivers_absent_is_empty(tmp_path):
    from wardline.core.waivers import load_project_waivers

    assert load_project_waivers(tmp_path) == ()


# --- P1 scheme-infra (S5) ---------------------------------------------------


def test_build_waivers_document_carries_scheme_and_version() -> None:
    doc = build_waivers_document([Waiver(fingerprint=_FP, reason="r", expires=date(2030, 1, 1))])
    assert doc["fingerprint_scheme"] == FINGERPRINT_SCHEME == "wlfp1"
    assert doc["version"] == WAIVERS_VERSION
    assert doc["waivers"][0]["fingerprint"] == _FP  # bare 64-hex
    assert ":" not in doc["waivers"][0]["fingerprint"]
    assert doc["waivers"][0]["reason"] == "r"
    assert doc["waivers"][0]["expires"] == "2030-01-01"


def test_build_waivers_document_omits_absent_expiry() -> None:
    doc = build_waivers_document([Waiver(fingerprint=_FP, reason="r")])
    assert "expires" not in doc["waivers"][0]


def test_add_waiver_writes_scheme_header(tmp_path) -> None:
    import yaml

    from wardline.core import paths
    from wardline.core.waivers import add_waiver

    add_waiver(paths.waivers_path(tmp_path), fingerprint=_FP, reason="ok", expires=None, root=tmp_path)
    raw = yaml.safe_load(paths.waivers_path(tmp_path).read_text())
    assert raw["fingerprint_scheme"] == FINGERPRINT_SCHEME
    assert raw["version"] == WAIVERS_VERSION


def test_second_add_preserves_scheme_header(tmp_path) -> None:
    import yaml

    from wardline.core import paths
    from wardline.core.waivers import add_waiver, load_project_waivers

    p = paths.waivers_path(tmp_path)
    add_waiver(p, fingerprint="a" * 64, reason="first", expires=None, root=tmp_path)
    add_waiver(p, fingerprint="b" * 64, reason="second", expires=None, root=tmp_path)
    raw = yaml.safe_load(p.read_text())
    assert raw["fingerprint_scheme"] == FINGERPRINT_SCHEME
    assert {w["fingerprint"] for w in raw["waivers"]} == {"a" * 64, "b" * 64}
    assert {w.fingerprint for w in load_project_waivers(tmp_path)} == {"a" * 64, "b" * 64}


def test_missing_scheme_on_nonempty_store_raises(tmp_path) -> None:
    import yaml

    from wardline.core import paths
    from wardline.core.waivers import load_project_waivers

    p = paths.waivers_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # An OLD (pre-P1) header-less store with real waivers must loud-fail.
    p.write_text(yaml.safe_dump({"waivers": [{"fingerprint": _FP, "reason": "r"}]}), encoding="utf-8")
    with pytest.raises(SchemeMismatchError) as ei:
        load_project_waivers(tmp_path)
    assert "waivers.yaml" in str(ei.value)
    assert "wardline rekey" in str(ei.value)


def test_wrong_scheme_raises(tmp_path) -> None:
    import yaml

    from wardline.core import paths
    from wardline.core.waivers import load_project_waivers

    p = paths.waivers_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp2", "version": WAIVERS_VERSION, "waivers": []}),
        encoding="utf-8",
    )
    with pytest.raises(SchemeMismatchError):
        load_project_waivers(tmp_path)


def test_present_but_empty_mapping_is_empty_no_error(tmp_path) -> None:
    from wardline.core import paths
    from wardline.core.waivers import load_project_waivers

    p = paths.waivers_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}\n", encoding="utf-8")  # empty-guard precedes the scheme check
    assert load_project_waivers(tmp_path) == ()
