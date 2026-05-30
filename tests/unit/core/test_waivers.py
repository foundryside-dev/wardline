from __future__ import annotations

from datetime import date

import pytest

from wardline.core.errors import ConfigError
from wardline.core.waivers import Waiver, WaiverSet, parse_waivers

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
    assert ws.match(_FP, date(2026, 5, 30)) is not None   # valid THROUGH expiry day
    assert ws.match(_FP, date(2026, 5, 31)) is None        # expired the day after
