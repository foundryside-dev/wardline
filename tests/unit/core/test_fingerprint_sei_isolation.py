"""Track 3 T3.3 — the SEI must NOT enter Wardline finding fingerprints.

The finding fingerprint is the stable cross-run identity baselines and waivers key
on; the SEI is a cross-tool BINDING key, a different concept. If the SEI ever leaked
into `compute_finding_fingerprint` it would silently invalidate every baseline/waiver
and break the warm/cold byte-identical guarantee. This guard locks the fingerprint's
input set: the golden hex below is computed INDEPENDENTLY of the function (see the
recipe in the comment), so any added/removed input — including an SEI — flips it.
"""

from __future__ import annotations

import inspect

import pytest

from wardline.core.finding import compute_finding_fingerprint

# Independently computed (NOT via compute_finding_fingerprint):
#   parts = ("PY-WL-101", "pkg/mod.py", "42", "pkg.mod.f", "EXTERNAL_RAW")
#   hashlib.sha256("\x00".join(parts).encode()).hexdigest()
_GOLDEN = "2f10c79df56839bfce49b31359bd392240cf146ef7280190baa5666d1ff25126"


def test_fingerprint_matches_independent_golden() -> None:
    # If anyone folds a new input (e.g. an SEI) into the fingerprint, this fails.
    fp = compute_finding_fingerprint(
        rule_id="PY-WL-101",
        path="pkg/mod.py",
        line_start=42,
        qualname="pkg.mod.f",
        taint_path="EXTERNAL_RAW",
    )
    assert fp == _GOLDEN


def test_fingerprint_has_no_sei_or_identity_parameter() -> None:
    # Structural guard: the fingerprint signature must not grow an SEI/identity input.
    params = set(inspect.signature(compute_finding_fingerprint).parameters)
    assert "sei" not in params
    assert "identity" not in params
    assert "binding_key" not in params
    assert params == {"rule_id", "path", "line_start", "qualname", "taint_path"}


def test_fingerprint_rejects_sei_keyword() -> None:
    # Belt-and-braces: passing an SEI keyword is a TypeError (no such input exists).
    with pytest.raises(TypeError):
        compute_finding_fingerprint(  # type: ignore[call-arg]
            rule_id="PY-WL-101", path="p.py", line_start=1, sei="loomweave:eid:deadbeef"
        )
