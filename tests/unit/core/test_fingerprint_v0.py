"""The frozen wlfp1 formula must reproduce the pre-P3 hash, byte-for-byte.

The golden is hand-rolled here (an independent ``hashlib`` line), NOT produced by
running the frozen copy — a self-sourced golden would pass even if the copy drifted.
The strong end-to-end non-circular check (reconstruction vs the real pre-P3 corpus)
lives in ``test_rekey_dual_fp.py``; this just pins the primitive + proves line_start
is load-bearing in v0 (the whole reason a rekey was needed).
"""

from __future__ import annotations

import hashlib

from wardline.core.fingerprint_v0 import FINGERPRINT_SCHEME_V0, compute_finding_fingerprint_v0


def _hand_rolled(rule_id: str, path: str, line_start: int | None, qualname: str, taint_path: str) -> str:
    parts = (rule_id, path, str(line_start), qualname, taint_path)
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


def test_v0_scheme_label_is_wlfp1() -> None:
    assert FINGERPRINT_SCHEME_V0 == "wlfp1"


def test_v0_matches_pre_change_hash() -> None:
    # Independent golden (hand-rolled, NOT via the frozen copy).
    golden = _hand_rolled("PY-WL-101", "pkg/mod.py", 42, "pkg.mod.f", "sink@4:9")
    assert golden == "0d0967ccef033475163c69bd56b1d754d48fb49590f9c8ca56e3e79f9f4f3b95"
    assert (
        compute_finding_fingerprint_v0(
            rule_id="PY-WL-101", path="pkg/mod.py", line_start=42, qualname="pkg.mod.f", taint_path="sink@4:9"
        )
        == golden
    )


def test_v0_line_start_is_load_bearing() -> None:
    # The entire reason for the rekey: in v0, shifting line_start changes the digest.
    a = compute_finding_fingerprint_v0(rule_id="PY-WL-101", path="m.py", line_start=42, qualname="m.f")
    b = compute_finding_fingerprint_v0(rule_id="PY-WL-101", path="m.py", line_start=43, qualname="m.f")
    assert a != b
    assert b == _hand_rolled("PY-WL-101", "m.py", 43, "m.f", "")


def test_v0_optional_fields_default_cleanly() -> None:
    assert len(compute_finding_fingerprint_v0(rule_id="WLN-ENGINE-X", path="a.py", line_start=None)) == 64
