"""Track 2 acceptance — the program-spec DoD's first gate.

An agent defines a NEW boundary type + a NEW rule end-to-end (in
``tests/grammar/fixtures/custom_grammar.py``, entirely outside ``src/wardline``)
and they fire correctly under ``build_analyzer(grammar=...)``. The litmus —
zero edits to ``_match`` / ``_ALL_RULE_CLASSES`` / ``_ENTRIES`` — is verified by
inspection of the whole-track diff (only new files were added for this fixture).
"""

from __future__ import annotations

from pathlib import Path

from grammar.fixtures.custom_grammar import GRAMMAR
from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer, build_analyzer

_FIX = Path(__file__).resolve().parent / "fixtures"
_TARGET = _FIX / "target_uses_sanitized.py"


def _scan(grammar=None):  # noqa: ANN001, ANN202
    analyzer = build_analyzer(grammar=grammar) if grammar is not None else WardlineAnalyzer()
    return analyzer, list(analyzer.analyze([_TARGET], WardlineConfig(), root=_FIX))


def test_agent_defined_boundary_and_rule_fire_end_to_end() -> None:
    analyzer, findings = _scan(GRAMMAR)
    fired = [f for f in findings if f.rule_id == "MYPROJ-001"]
    assert len(fired) == 1, [f.rule_id + ":" + (f.qualname or "") for f in findings if f.kind == Kind.DEFECT]
    assert fired[0].qualname == "target_uses_sanitized.leaks"
    assert fired[0].kind == Kind.DEFECT
    # The @sanitized boundary seeded the taint the rule keyed on: 'leaks' resolved
    # anchored (the custom boundary type was recognized), 'clean' produced nothing.
    assert analyzer.last_context is not None
    assert analyzer.last_context.taint_provenance["target_uses_sanitized.leaks"].source == "anchored"
    assert "target_uses_sanitized.clean" not in {f.qualname for f in fired}


def test_custom_rule_absent_under_default_grammar() -> None:
    # Without the agent's grammar, MYPROJ-001 cannot fire — and @myproj.trust.sanitized
    # is unknown vocabulary, so 'clean'/'leaks' are not anchored on it.
    _, findings = _scan(None)
    assert not [f for f in findings if f.rule_id == "MYPROJ-001"]
