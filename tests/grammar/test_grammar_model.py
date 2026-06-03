"""Track 2 T2.1 — the trust-grammar meta-model.

Pins the shape of ``BoundaryType`` / ``LevelArg`` / ``TrustGrammar`` /
``default_grammar()`` and the consistency invariant that the builtin boundary
types cannot drift from the released ``REGISTRY`` (design spec §3).
"""

from __future__ import annotations

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.scanner.grammar import (
    BUILTIN_BOUNDARY_TYPES,
    BoundaryType,
    LevelArg,
    default_grammar,
)
from wardline.scanner.taint.provider import FunctionTaint

_EXPECTED_ARGS = {
    "external_boundary": set(),
    "trust_boundary": {"to_level"},
    "trusted": {"level"},
}


def test_default_grammar_has_three_builtins_and_all_rules() -> None:
    g = default_grammar()
    assert tuple(bt.canonical_name for bt in g.boundary_types) == (
        "external_boundary",
        "trust_boundary",
        "trusted",
    )
    assert [r.rule_id for r in g.rules] == [
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
    ]


def test_builtin_boundary_types_align_with_registry() -> None:
    # One source of truth: builtin names + group mirror REGISTRY; arg names are the
    # known per-decorator set. Drift in either is caught here (and at import time).
    by_name = {bt.canonical_name: bt for bt in BUILTIN_BOUNDARY_TYPES}
    assert set(by_name) == set(REGISTRY)
    for name, entry in REGISTRY.items():
        bt = by_name[name]
        assert bt.group == entry.group
        assert bt.builtin is True
        assert {la.arg_name for la in bt.level_args} == _EXPECTED_ARGS[name]


def test_seed_semantics_round_trip() -> None:
    by_name = {bt.canonical_name: bt for bt in BUILTIN_BOUNDARY_TYPES}
    assert by_name["external_boundary"].seed({}) == FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)
    assert by_name["trust_boundary"].seed({"to_level": TaintState.ASSURED}) == FunctionTaint(
        TaintState.EXTERNAL_RAW, TaintState.ASSURED
    )
    assert by_name["trusted"].seed({"level": TaintState.INTEGRAL}) == FunctionTaint(
        TaintState.INTEGRAL, TaintState.INTEGRAL
    )


def test_trusted_default_level_is_integral() -> None:
    by_name = {bt.canonical_name: bt for bt in BUILTIN_BOUNDARY_TYPES}
    (level_arg,) = by_name["trusted"].level_args
    assert level_arg.default == TaintState.INTEGRAL
    # trust_boundary's to_level is REQUIRED (no default => fail-closed when unreadable)
    (to_level_arg,) = by_name["trust_boundary"].level_args
    assert to_level_arg.default is None


def test_extend_appends_never_replaces() -> None:
    custom = BoundaryType(
        canonical_name="sanitized",
        module_prefix="myproj.trust",
        group=1,
        level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),
        seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    base = default_grammar()
    g = base.extend(boundary_types=(custom,))
    assert g.boundary_types[: len(base.boundary_types)] == base.boundary_types
    assert g.boundary_types[-1] is custom
    assert g.rules == base.rules  # rules untouched when only boundary types extended
