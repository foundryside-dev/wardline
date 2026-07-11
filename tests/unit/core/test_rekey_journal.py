"""P4 S6 — the migration journal: remap + per-leg done-flags, roundtrip, resume skips done."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.core import paths
from wardline.core.errors import ConfigError
from wardline.core.rekey import (
    LEG_NAMES,
    FingerprintRemap,
    Journal,
    RekeyCollision,
    load_journal,
    new_journal,
    resume_rekey,
    write_journal,
)


def _journal_doc(*, legs: object = None, schema_version: object = 1) -> dict:
    doc: dict = {"schema_version": schema_version, "remap": {}}
    if legs is not None:
        doc["legs"] = legs
    return doc


def _leg_docs(names: tuple[str, ...] = LEG_NAMES) -> list[dict]:
    return [{"name": name, "done": False, "carried": [], "orphaned": [], "debt": None} for name in names]


def _write_raw(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


class _EmissionProbe:
    def __init__(self) -> None:
        self.called = False

    def emit(self, *_args: object, **_kwargs: object) -> None:
        self.called = True
        raise AssertionError("invalid journal reached Filigree before validation")


def test_journal_roundtrip_and_resume_skips_done(tmp_path: Path) -> None:
    a, na = "a" * 64, "1" * 64
    j = new_journal([FingerprintRemap(old_fp=a, new_fp=na, rule_id="PY-WL-108", path="m.py", qualname="m.f")])
    assert [leg.name for leg in j.legs] == ["baseline", "judged", "waivers", "filigree"]
    assert j.next_pending_leg() == "baseline"
    assert j.fingerprint_scheme_from == "wlfp1" and j.fingerprint_scheme_to == "wlfp2"

    j.leg("baseline").done = True
    j.leg("baseline").carried = [a]
    j.snapshot_prescheme = True  # a scheme-less (pre-P1) snapshot — must persist for --resume display
    assert j.next_pending_leg() == "judged"

    p = tmp_path / "migration_journal.yaml"
    write_journal(p, j, root=tmp_path)
    loaded = load_journal(p)
    assert loaded.remap == {a: na}
    assert loaded.leg("baseline").done is True
    assert loaded.leg("baseline").carried == [a]
    assert loaded.snapshot_prescheme is True  # the prescheme caution survives the roundtrip
    assert loaded.next_pending_leg() == "judged"

    for leg in loaded.legs:
        leg.done = True
    assert loaded.complete


def test_journal_snapshot_prescheme_defaults_false_when_absent(tmp_path: Path) -> None:
    # A journal written before this field existed (no key) loads as False — backward compatible.
    j = Journal(remap={})
    assert j.snapshot_prescheme is False
    p = tmp_path / "j.yaml"
    write_journal(p, j, root=tmp_path)
    assert load_journal(p).snapshot_prescheme is False


def test_journal_persists_collisions(tmp_path: Path) -> None:
    j = Journal(remap={}, collisions=[RekeyCollision(new_fp="1" * 64, old_fps=("a" * 64, "b" * 64))])
    p = tmp_path / "j.yaml"
    write_journal(p, j, root=tmp_path)
    loaded = load_journal(p)
    assert len(loaded.collisions) == 1
    assert loaded.collisions[0].old_fps == ("a" * 64, "b" * 64)


def test_journal_persists_fanout_collisions(tmp_path: Path) -> None:
    j = Journal(
        remap={},
        collisions=[
            RekeyCollision(
                new_fp=None,
                old_fps=("a" * 64,),
                new_fps=("1" * 64, "2" * 64),
            )
        ],
    )
    p = tmp_path / "j.yaml"
    write_journal(p, j, root=tmp_path)
    loaded = load_journal(p)
    assert len(loaded.collisions) == 1
    assert loaded.collisions[0].new_fp is None
    assert loaded.collisions[0].old_fps == ("a" * 64,)
    assert loaded.collisions[0].new_fps == ("1" * 64, "2" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    (("fingerprint_scheme_from", "wlfp999"), ("fingerprint_scheme_to", "wlfp999")),
)
def test_journal_rejects_an_unknown_fingerprint_scheme(tmp_path: Path, field: str, value: str) -> None:
    j = Journal(remap={})
    p = tmp_path / "j.yaml"
    write_journal(p, j, root=tmp_path)
    text = p.read_text(encoding="utf-8")
    p.write_text(text.replace(f"{field}: wlfp1" if field.endswith("from") else f"{field}: wlfp2", f"{field}: {value}"))

    with pytest.raises(ConfigError, match=f"unsupported migration journal schemes.*{value}"):
        load_journal(p)


@pytest.mark.parametrize(
    ("case", "names"),
    (
        ("missing", LEG_NAMES[:-1]),
        ("duplicate", ("baseline", "judged", "waivers", "waivers")),
        ("reordered", ("filigree", "baseline", "judged", "waivers")),
        ("unknown", ("baseline", "judged", "waivers", "mystery")),
    ),
)
def test_resume_rejects_noncanonical_legs_without_mutation(tmp_path: Path, case: str, names: tuple[str, ...]) -> None:
    live = paths.baseline_path(tmp_path)
    live.parent.mkdir(parents=True, exist_ok=True)
    live.write_bytes(b"live-before")
    journal_path = paths.migration_journal_path(tmp_path)
    _write_raw(journal_path, _journal_doc(legs=_leg_docs(names)))
    before = {live: live.read_bytes(), journal_path: journal_path.read_bytes()}
    filigree = _EmissionProbe()

    with pytest.raises(ConfigError, match="journal legs must be exactly"):
        resume_rekey(tmp_path, findings=[], filigree=filigree)

    assert {path: path.read_bytes() for path in before} == before, case
    assert not filigree.called


@pytest.mark.parametrize("schema_version", (2, "1", True))
def test_resume_rejects_bad_schema_version_without_mutation(tmp_path: Path, schema_version: object) -> None:
    live = paths.baseline_path(tmp_path)
    live.parent.mkdir(parents=True, exist_ok=True)
    live.write_bytes(b"live-before")
    journal_path = paths.migration_journal_path(tmp_path)
    _write_raw(journal_path, _journal_doc(legs=_leg_docs(), schema_version=schema_version))
    before = {live: live.read_bytes(), journal_path: journal_path.read_bytes()}

    with pytest.raises(ConfigError, match="unsupported migration journal schema_version"):
        resume_rekey(tmp_path)

    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("legs", (None, []))
def test_absent_or_empty_legs_default_to_canonical_sequence(tmp_path: Path, legs: object) -> None:
    path = tmp_path / "journal.yaml"
    doc = _journal_doc() if legs is None else _journal_doc(legs=legs)
    _write_raw(path, doc)

    assert tuple(leg.name for leg in load_journal(path).legs) == LEG_NAMES


@pytest.mark.parametrize(
    "legs",
    (
        "baseline",
        [1],
        [{"name": name, "done": "yes"} for name in LEG_NAMES],
        [{"name": name, "carried": 1} for name in LEG_NAMES],
    ),
)
def test_malformed_leg_types_raise_config_error(tmp_path: Path, legs: object) -> None:
    path = tmp_path / "journal.yaml"
    _write_raw(path, _journal_doc(legs=legs))

    with pytest.raises(ConfigError, match="malformed migration journal.*legs"):
        load_journal(path)
