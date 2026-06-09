"""P4 S3 — new_fp injectivity: per-collision orphan-and-report, NEVER whole-run abort."""

from __future__ import annotations

from wardline.core.rekey import FingerprintRemap, build_remap


def _rm(old: str, new: str, rule: str = "PY-WL-108", q: str = "m.f") -> FingerprintRemap:
    return FingerprintRemap(old_fp=old, new_fp=new, rule_id=rule, path="m.py", qualname=q)


def test_collapsing_remap_reports_and_continues() -> None:
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    shared, ok = "1" * 64, "2" * 64
    # a and b are distinct under wlfp1 but collapse to `shared` under wlfp2.
    res = build_remap([_rm(a, shared), _rm(b, shared), _rm(c, ok)])

    assert len(res.collisions) == 1
    assert res.collisions[0].new_fp == shared
    assert res.collisions[0].old_fps == (a, b)
    assert "WLN-ENGINE-FINGERPRINT-COLLISION" in res.collisions[0].message
    # BOTH colliding old_fps are orphaned (neither verdict carried)...
    assert a not in res.old_to_new and b not in res.old_to_new
    # ...and the rest of the migration proceeds.
    assert res.old_to_new == {c: ok}


def test_clean_remap_has_no_collisions() -> None:
    a, b = "a" * 64, "b" * 64
    res = build_remap([_rm(a, "1" * 64), _rm(b, "2" * 64)])
    assert res.collisions == ()
    assert res.old_to_new == {a: "1" * 64, b: "2" * 64}


def test_identical_finding_seen_twice_is_not_a_collision() -> None:
    # Same (old_fp, new_fp) twice is idempotent, not a collision.
    a = "a" * 64
    res = build_remap([_rm(a, "1" * 64), _rm(a, "1" * 64)])
    assert res.collisions == ()
    assert res.old_to_new == {a: "1" * 64}
