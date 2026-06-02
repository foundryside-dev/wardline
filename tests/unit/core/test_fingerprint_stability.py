"""Fingerprint stability — pin the *real* contract, both directions.

CLAUDE.md calls a fingerprint change "breaking" (it silently invalidates every
baseline and waiver). The fingerprint inputs are
``(rule_id, path, line_start, qualname, taint_path)`` — and ``line_start`` IS an
input (the function ``def`` line for declaration-anchored rules; the call line
for sink rules). So the contract is NOT "any cosmetic edit keeps the fingerprint":

  * **Anchor-preserving edits** — rename a local, add a trailing comment, add or
    edit code *below* the finding's anchor line — keep the fingerprint
    byte-identical. This is the property baselines/waivers rely on.
  * **An edit that shifts the anchor line** (inserting a blank line *above* the
    flagged ``def``/call, moving the function down) DOES change the fingerprint.
    This is by design: ``line_start`` is a fingerprint input, and CLAUDE.md
    forbids "fixing" that (making the fingerprint line-independent would itself
    be the breaking change). We pin it as intended behavior, not a bug.
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


def test_declaration_line_shift_changes_fingerprint(tmp_path: Path) -> None:
    # Inserting a blank line above the def shifts line_start -> different fingerprint.
    # Documented as intended: line_start is a fingerprint input (CLAUDE.md).
    base = _fingerprints(tmp_path, _DECL_BASE, "PY-WL-102")
    shifted = _fingerprints(tmp_path, _DECL_LINE_SHIFTING, "PY-WL-102")
    assert base and shifted and base != shifted


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


def test_sink_call_line_shift_changes_fingerprint(tmp_path: Path) -> None:
    base = _fingerprints(tmp_path, _SINK_BASE, "PY-WL-107")
    shifted = _fingerprints(tmp_path, _SINK_LINE_SHIFTING, "PY-WL-107")
    assert base and shifted and base != shifted
