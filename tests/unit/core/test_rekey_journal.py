"""P4 S6 — the migration journal: remap + per-leg done-flags, roundtrip, resume skips done."""

from __future__ import annotations

from pathlib import Path

from wardline.core.rekey import FingerprintRemap, Journal, RekeyCollision, load_journal, new_journal, write_journal


def test_journal_roundtrip_and_resume_skips_done(tmp_path: Path) -> None:
    a, na = "a" * 64, "1" * 64
    j = new_journal([FingerprintRemap(old_fp=a, new_fp=na, rule_id="PY-WL-108", path="m.py", qualname="m.f")])
    assert [leg.name for leg in j.legs] == ["baseline", "judged", "waivers", "filigree"]
    assert j.next_pending_leg() == "baseline"
    assert j.fingerprint_scheme_from == "wlfp1" and j.fingerprint_scheme_to == "wlfp2"

    j.leg("baseline").done = True
    j.leg("baseline").carried = [a]
    assert j.next_pending_leg() == "judged"

    p = tmp_path / "migration_journal.yaml"
    write_journal(p, j, root=tmp_path)
    loaded = load_journal(p)
    assert loaded.remap == {a: na}
    assert loaded.leg("baseline").done is True
    assert loaded.leg("baseline").carried == [a]
    assert loaded.next_pending_leg() == "judged"

    for leg in loaded.legs:
        leg.done = True
    assert loaded.complete


def test_journal_persists_collisions(tmp_path: Path) -> None:
    j = Journal(remap={}, collisions=[RekeyCollision(new_fp="1" * 64, old_fps=("a" * 64, "b" * 64))])
    p = tmp_path / "j.yaml"
    write_journal(p, j, root=tmp_path)
    loaded = load_journal(p)
    assert len(loaded.collisions) == 1
    assert loaded.collisions[0].old_fps == ("a" * 64, "b" * 64)
