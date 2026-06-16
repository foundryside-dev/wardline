"""C-13 — fail-degraded, never fail-dead: one hostile file never kills a run.

Federation convention C-13 (hub `conventions.md`, ratified `b0eee6e`; hub issue
weft-b181c75e39): a member tool that walks or parses project source MUST NOT
hard-fail the whole run on one hostile input. Per file: skip + flag + continue —
the skip is an IN-BAND marker in the result envelope (a finding, never only a log
line), and the run completes over the remaining files.

This is wardline's adoption fixture: the ``nesting_bomb``-class corpus that killed
legis's ``policy-boundary-check`` with an uncaught RecursionError (dogfood-4 A2)
and that loomweave's python extractor degrades to ``too_complex`` (the C-13
reference, `d5baac5`). Reference implementations: loomweave
``plugins/python/.../extractor.py``; legis ``policy/boundary_scan.py`` 58-80
(``POLICY_BOUNDARY_FILE_TOO_COMPLEX``).

The bombs are GENERATED here (a 20,000-term line has no business in git history);
``lacuna/specimen/nesting_bomb.py`` is the live twin this corpus mirrors.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan

# In-band per-file degrade markers the engine may legitimately emit for a hostile
# file, in any stage: parse (PARSE-ERROR for parser-level rejections,
# FILE-SKIPPED for RecursionError), per-entity L2 (FUNCTION-SKIPPED), or the
# unexpected-exception isolation net (FILE-FAILED).
_DEGRADE_RULES = frozenset(
    {
        "WLN-ENGINE-PARSE-ERROR",
        "WLN-ENGINE-FILE-SKIPPED",
        "WLN-ENGINE-FUNCTION-SKIPPED",
        "WLN-ENGINE-FILE-FAILED",
    }
)

# A healthy violating neighbour: its PY-WL-101 finding proves the scan kept going
# and kept ANALYZING after meeting the hostile files (alphabetically the bombs
# sort both before and after it).
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)

_BINOP_TERMS = 20_000  # parses fine; blows naive recursive AST visitors (killed legis)
_NESTING_DEPTH = 600  # deeply nested if blocks; rejected at the parser layer


def _hostile_corpus(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "middle_clean.py").write_text(_LEAKY, encoding="utf-8")
    # (a) deeply nested if blocks — hostile to the parser/compiler layer.
    nested = ["x = 1"]
    nested += ["    " * i + f"if x > {i}:" for i in range(_NESTING_DEPTH)]
    nested += ["    " * _NESTING_DEPTH + "pass"]
    (proj / "aaa_nesting_bomb.py").write_text("\n".join(nested) + "\n", encoding="utf-8")
    # (b) the 20,000-term BinOp chain, module-level (lacuna's specimen/nesting_bomb.py
    # shape) and inside a function body (so the per-entity walks meet it too).
    chain = "+".join(["1"] * _BINOP_TERMS)
    (proj / "aab_binop_bomb_module.py").write_text(f"BOMB = {chain}\n", encoding="utf-8")
    (proj / "zzz_binop_bomb_func.py").write_text(f"def f():\n    return {chain}\n", encoding="utf-8")
    return proj


_HOSTILE_FILES = ("aaa_nesting_bomb.py", "aab_binop_bomb_module.py", "zzz_binop_bomb_func.py")


def test_hostile_corpus_scan_completes_flags_and_continues(tmp_path: Path) -> None:
    proj = _hostile_corpus(tmp_path)

    # COMPLETES: no RecursionError (or anything else) escapes the scan.
    result = run_scan(proj, confine_to_root=True)

    # FLAGS: every hostile file carries an in-band degrade marker in the result
    # envelope — a finding the consumer can see, never only a log line.
    by_path = {p: [f for f in result.findings if f.location.path == p] for p in _HOSTILE_FILES}
    for path, findings in by_path.items():
        markers = [f for f in findings if f.rule_id in _DEGRADE_RULES]
        assert markers, f"{path}: hostile file skipped with NO in-band marker (C-13 violation)"
        # Fail-closed posture: unscanned code must not read GREEN — the marker is a
        # gate-eligible ERROR DEFECT, not an ignorable FACT.
        assert all(m.kind is Kind.DEFECT and m.severity is Severity.ERROR for m in markers), path

    # CONTINUES: the healthy neighbour's findings are still reported.
    leaky = [f for f in result.findings if f.rule_id == "PY-WL-101" and f.location.path == "middle_clean.py"]
    assert leaky, "scan lost the healthy file's findings after meeting the hostile ones"

    # The degraded scope is visible in the envelope (count), per C-10(a).
    assert result.summary.unanalyzed >= len(_HOSTILE_FILES) - 1  # FUNCTION-SKIPPED counts per entity, not per file
    assert result.files_scanned == 4  # all four files were DISCOVERED, none aborted the run


def test_hostile_corpus_gate_trips_rather_than_reads_green(tmp_path: Path) -> None:
    # C-13 + the fail-closed gate: a degraded scan must be able to TRIP an ERROR
    # gate (the skipped files were never analyzed), never silently pass as green.
    proj = _hostile_corpus(tmp_path)
    result = run_scan(proj, confine_to_root=True)
    degrade_markers = [f for f in result.findings if f.rule_id in _DEGRADE_RULES]
    assert degrade_markers
    assert {f.severity for f in degrade_markers} == {Severity.ERROR}
