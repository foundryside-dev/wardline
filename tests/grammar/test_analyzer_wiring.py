"""Track 2 T2.2 — rule set + analyzer wired from a TrustGrammar.

``build_default_registry`` takes its rules from the grammar (default = builtins);
``build_analyzer(grammar=...)`` threads both boundary types and rules. The no-arg /
default paths stay behavior-identical to today (the oracle proves the findings).
"""

from __future__ import annotations

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer, build_analyzer
from wardline.scanner.grammar import default_grammar
from wardline.scanner.rules import build_default_registry

_BUILTIN_IDS = [
    "PY-WL-101",
    "PY-WL-102",
    "PY-WL-103",
    "PY-WL-104",
    "PY-WL-110",
    "PY-WL-109",
    "PY-WL-105",
    "PY-WL-106",
    "PY-WL-107",
    "PY-WL-108",
    "PY-WL-112",
    "PY-WL-111",
    "PY-WL-113",
    "PY-WL-114",
    "PY-WL-115",
    "PY-WL-116",
    "PY-WL-117",
    "PY-WL-118",
    "PY-WL-119",
    "PY-WL-120",
    "PY-WL-121",
    "PY-WL-122",
    "PY-WL-123",
    "PY-WL-124",
    "PY-WL-125",
    "PY-WL-126",
]


def test_build_default_registry_default_is_builtin_rules() -> None:
    reg = build_default_registry(WardlineConfig())  # no rules= -> builtins
    assert [r.rule_id for r in reg.rules] == _BUILTIN_IDS


def test_build_default_registry_uses_grammar_rules() -> None:
    reg = build_default_registry(WardlineConfig(), rules=default_grammar().rules)
    assert [r.rule_id for r in reg.rules] == _BUILTIN_IDS


def test_build_analyzer_default_is_builtin_grammar() -> None:
    # build_analyzer() with no grammar == builtins == bare WardlineAnalyzer().
    assert build_analyzer()._provider.fingerprint() == WardlineAnalyzer()._provider.fingerprint()


def test_build_analyzer_threads_grammar_into_provider() -> None:
    from wardline.core.taints import TaintState
    from wardline.scanner.grammar import BoundaryType, LevelArg
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        "sanitized",
        "myproj.trust",
        1,
        (LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),
        lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
    # custom grammar -> distinct fingerprint from builtins (provider got the types)
    assert analyzer._provider.fingerprint() != WardlineAnalyzer()._provider.fingerprint()
