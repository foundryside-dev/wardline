"""P10 — the malformity asymmetry, pinned by name.

Malformed BUILTIN declarations are ERROR DEFECTs (PY-WL-130 for call shape,
PY-WL-114 for readable-but-invalid levels): the builtin vocabulary is provable,
so malformity gates. Malformed CUSTOM/pack declarations are FACTs
(WLN-ENGINE-UNPROVABLE-BOUNDARY): the custom path is the unprovable one, so it
observes without gating. Neither channel may leak into the other.

This module also carries the ONE custom-side cell the drop-coverage matrix
cannot reach. That matrix is builtin-only by construction (run_scan loads no
custom grammar, and _MARKER_CHANNELS holds three builtin channels), so the
custom arm of read_level's positional guard is pinned here — the axis on which
a dropped guard mints a trusted seed with nothing red."""

from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

_CUSTOM = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
    seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
    builtin=False,
)


def test_builtin_malformed_call_is_an_error_defect_and_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    hits = [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert len(hits) == 1 and hits[0].severity is Severity.ERROR and hits[0].kind is Kind.DEFECT
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]


def test_custom_malformed_marker_is_a_fact_and_never_pywl130(tmp_path: Path) -> None:
    # The exact construction tests/grammar/test_unprovable_boundary.py:19-26 uses.
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG, extra=1)\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    facts = [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert len(facts) == 1 and facts[0].severity is Severity.NONE and facts[0].kind is Kind.FACT
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_custom_level_marker_with_foreign_metadata_remains_unprovable(tmp_path: Path) -> None:
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level='ASSURED', extra=1)\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_custom_zero_level_metadata_is_ignored_and_still_seeds(tmp_path: Path) -> None:
    custom = BoundaryType(
        canonical_name="source",
        module_prefix="myproj.trust",
        group=1,
        level_args=(),
        seed=lambda _lv: FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW),
        builtin=False,
    )
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.source(owner='payments')\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.EXTERNAL_RAW


def test_custom_positional_argument_never_takes_a_defaulted_level(tmp_path: Path) -> None:
    # THE CUSTOM SIDE'S POSITIONAL GUARD, end to end — and the one cell on this
    # axis, because the drop-coverage matrix beside it is builtin-only by
    # construction (`run_scan` loads no custom grammar). `call_shape_offences`
    # and PY-WL-130 are builtin-only by design (spec §4.2.1; Global Constraints'
    # hard custom-pack gate), so `read_level`'s `if deco.args: return
    # _unreadable(None)` (Task 2 Step 1) is the ONLY thing between a positional
    # custom marker and a minted trusted seed.
    #
    # This pack declares a DEFAULTED `LevelArg` — the shape wardline's own
    # builtins use (boundary_types.py:108, :125), and therefore the one a pack
    # author copies. Drop the guard and both rows below take `_defaulted()`,
    # seeding ASSURED with no finding on any channel. Every custom `LevelArg` in
    # this tree passes `default=None` (measured 2026-08-10), so nothing else
    # would red: this row exists precisely because zero reds is the mechanism by
    # which that regression ships.
    custom = BoundaryType(
        canonical_name="sanitized",
        module_prefix="myproj.trust",
        group=1,
        level_args=(
            LevelArg(
                "to_level",
                frozenset({TaintState.GUARDED, TaintState.ASSURED}),
                TaintState.ASSURED,
            ),
        ),
        seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    for deco in ("@myproj.trust.sanitized('ASSURED')", "@myproj.trust.sanitized(*ARGS)"):
        f = tmp_path / "m.py"
        f.write_text(
            f"import myproj.trust\nARGS = ('ASSURED',)\n{deco}\ndef g(p):\n    return p\n",
            encoding="utf-8",
        )
        analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
        findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
        assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"], deco
        assert not [x for x in findings if x.rule_id == "PY-WL-130"], deco
        assert analyzer.last_context is not None
        assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW, deco
