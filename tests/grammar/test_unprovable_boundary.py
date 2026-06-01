"""Track 2 T2.4 — soundness inheritance for the extension plane.

An agent-defined boundary the engine cannot prove (a required level unreadable)
seeds the fail-closed ``UNKNOWN_RAW`` AND emits an observable
``WLN-ENGINE-UNPROVABLE-BOUNDARY`` FACT — never a silent false-green. The same
shape on a BUILTIN boundary stays silent (no FACT), preserving the byte-identity
oracle (design spec §4).
"""

from __future__ import annotations

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
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

_RULE_ID = "WLN-ENGINE-UNPROVABLE-BOUNDARY"


def test_unprovable_custom_emits_fact_and_unknown_seed(tmp_path) -> None:
    f = tmp_path / "m.py"
    # to_level is a bare Name (CFG) — not statically readable -> fail-closed.
    f.write_text("import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef g(p):\n    return p\n")
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)

    facts = [x for x in findings if x.rule_id == _RULE_ID]
    assert len(facts) == 1
    assert facts[0].kind == Kind.FACT
    assert facts[0].severity == Severity.NONE
    assert facts[0].qualname == "m.g"
    assert facts[0].properties.get("boundary") == "sanitized"
    # seeded the fail-closed UNKNOWN_RAW (never over-trusted)
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_provable_custom_emits_no_fact(tmp_path) -> None:
    f = tmp_path / "m.py"
    f.write_text("import myproj.trust\n@myproj.trust.sanitized(to_level='GUARDED')\ndef g(p):\n    return p\n")
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert not [x for x in findings if x.rule_id == _RULE_ID]


def test_unprovable_builtin_emits_no_fact(tmp_path) -> None:
    # Oracle-preserving twin: an unreadable BUILTIN level stays silent (no FACT).
    f = tmp_path / "m.py"
    f.write_text(
        "from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\ndef g(p):\n    return p\n"
    )
    analyzer = build_analyzer()  # builtins only
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert not [x for x in findings if x.rule_id == _RULE_ID]
