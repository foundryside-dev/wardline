"""P1 scheme-infra S1: the self-describing fingerprint scheme stamp.

The fingerprint VALUE is unchanged here (still the wlfp1 hash, line_start IN) —
this only adds the format layer (``scheme:hex``) applied at the wire/store
boundary. ``compute_finding_fingerprint`` keeps returning bare 64-hex; the
prefix is never stored in-memory.
"""

from __future__ import annotations

import pytest

from wardline.core.finding import (
    FINGERPRINT_SCHEME,
    compute_finding_fingerprint,
    format_fingerprint,
    parse_fingerprint,
)


def test_scheme_constant_is_wlfp1() -> None:
    assert FINGERPRINT_SCHEME == "wlfp1"


def test_format_fingerprint_prefixes_with_colon() -> None:
    assert format_fingerprint("wlfp1", "ab" * 32) == "wlfp1:" + "ab" * 32


def test_parse_round_trips_format() -> None:
    h = "cd" * 32
    assert parse_fingerprint(format_fingerprint(FINGERPRINT_SCHEME, h)) == (FINGERPRINT_SCHEME, h)


def test_parse_returns_scheme_verbatim_does_not_validate_scheme_value() -> None:
    # parse is a pure FORMAT parser — scheme-mismatch is the store loaders' job
    # (SchemeMismatchError), not parse_fingerprint's. It returns whatever scheme
    # token is present so a reader can compare it itself.
    h = "ab" * 32
    assert parse_fingerprint(f"wlfp2:{h}") == ("wlfp2", h)


@pytest.mark.parametrize(
    "bad",
    [
        "ab" * 32,  # no colon (a bare fingerprint is not the prefixed form)
        "wlfp1:" + "ab" * 31,  # hex too short (62)
        "wlfp1:" + "ab" * 33,  # hex too long (66)
        "wlfp1:" + "AB" * 32,  # uppercase hex rejected
        "wlfp1:" + "zz" * 32,  # non-hex chars
        ":" + "ab" * 32,  # empty scheme
        "wlfp1:" + "ab" * 31 + "g0",  # 64 chars but non-hex
    ],
)
def test_parse_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_fingerprint(bad)


def test_compute_fingerprint_stays_bare_64_hex() -> None:
    fp = compute_finding_fingerprint(rule_id="PY-WL-101", path="a.py", line_start=3)
    assert ":" not in fp
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)
