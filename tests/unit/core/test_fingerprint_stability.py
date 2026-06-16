"""Fingerprint stability — pin the *real* contract, both directions.

A fingerprint change is "breaking" (it silently invalidates every baseline and
waiver). The fingerprint inputs are ``(rule_id, path, qualname, taint_path)`` —
``line_start`` is NOT hashed (wlfp2, wardline-8654423823). Multi-emit rules carry
an ENTITY-RELATIVE discriminator in ``taint_path`` (``node.lineno -
entity.location.line_start`` + the lexical span). So the contract is:

  * **Anchor-preserving edits** — rename a local, add a trailing comment, edit
    code *below* the finding — keep the fingerprint byte-identical.
  * **Whole-entity moves** — inserting a blank line / comment ABOVE the flagged
    ``def`` shifts every absolute line but keeps the fingerprint, because the
    discriminator is relative to the enclosing entity. This is the churn fix
    (wardline-8654423823): a benign edit above a function no longer rekeys it.
  * **In-entity offset shifts** — inserting a statement INSIDE the function,
    ABOVE a multi-emit node (a sink call), DOES change that finding's
    fingerprint, because the node's offset relative to its def moved. This is the
    accepted limitation: entity-relative, not move-stable in the strong sense.
    (A def-anchored singleton, taint_path=None, is immune to in-function edits.)
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

_IMPORTS = "from wardline.decorators import external_boundary, trust_boundary, trusted\n"


def _fingerprints(tmp_path: Path, snippet: str, rule_id: str) -> list[str]:
    src = tmp_path / "m.py"
    src.write_text(_IMPORTS + textwrap.dedent(snippet), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([src], WardlineConfig(), root=tmp_path)
    return [f.fingerprint for f in findings if f.rule_id == rule_id]


# --- declaration-anchored: PY-WL-102 (anchor = the def line) -----------------

_DECL_BASE = """
@trust_boundary(to_level='ASSURED')
def v(p):
    data = p
    return data
"""

_DECL_ANCHOR_PRESERVING = """
@trust_boundary(to_level='ASSURED')
def v(p):
    payload = p  # renamed local + trailing comment
    return payload
def added_below():
    return 1
"""

_DECL_LINE_SHIFTING = """

@trust_boundary(to_level='ASSURED')
def v(p):
    data = p
    return data
"""


def test_declaration_anchor_preserving_edits_keep_fingerprint(tmp_path: Path) -> None:
    base = _fingerprints(tmp_path, _DECL_BASE, "PY-WL-102")
    preserved = _fingerprints(tmp_path, _DECL_ANCHOR_PRESERVING, "PY-WL-102")
    assert base and base == preserved


def test_declaration_whole_entity_move_keeps_fingerprint(tmp_path: Path) -> None:
    # A blank line ABOVE the def moves the whole entity down. Under wlfp2 the
    # def-anchored singleton (taint_path=None, qualname-keyed) is invariant to that
    # — the churn fix (wardline-8654423823): a benign edit above a function no
    # longer rekeys its baseline/waiver/Filigree join.
    base = _fingerprints(tmp_path, _DECL_BASE, "PY-WL-102")
    shifted = _fingerprints(tmp_path, _DECL_LINE_SHIFTING, "PY-WL-102")
    assert base and shifted and base == shifted


# --- call-anchored: PY-WL-107 (anchor = the sink call line) ------------------

_SINK_BASE = """
@external_boundary
def read_raw(p):
    return p
@trusted(level='ASSURED')
def f(p):
    eval(read_raw(p))
"""

_SINK_ANCHOR_PRESERVING = """
@external_boundary
def read_raw(p):
    return p
@trusted(level='ASSURED')
def f(p):
    eval(read_raw(p))  # trailing comment leaves the call line put
"""

_SINK_LINE_SHIFTING = """
@external_boundary
def read_raw(p):
    return p
@trusted(level='ASSURED')
def f(p):
    x = p  # an extra statement pushes the sink call down a line
    eval(read_raw(p))
"""


def test_sink_anchor_preserving_edits_keep_fingerprint(tmp_path: Path) -> None:
    base = _fingerprints(tmp_path, _SINK_BASE, "PY-WL-107")
    preserved = _fingerprints(tmp_path, _SINK_ANCHOR_PRESERVING, "PY-WL-107")
    assert base and base == preserved


def test_sink_in_entity_offset_shift_changes_fingerprint(tmp_path: Path) -> None:
    # A statement inserted INSIDE the function, ABOVE the sink call, moves the
    # call's offset relative to its def -> different fingerprint. The accepted
    # entity-relative limitation (wardline-8654423823): not move-stable in the
    # strong sense. (A whole-entity move ABOVE the def keeps it — see the
    # entity-relative driver in test_rekey_mutation_pairs.)
    base = _fingerprints(tmp_path, _SINK_BASE, "PY-WL-107")
    shifted = _fingerprints(tmp_path, _SINK_LINE_SHIFTING, "PY-WL-107")
    assert base and shifted and base != shifted
