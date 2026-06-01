# tests/unit/scanner/taint/test_function_level.py
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity, discover_file_entities
from wardline.scanner.taint.function_level import FunctionSeed, seed_function_taints
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
    SeedResult,
)


def _entities(src: str) -> list[Entity]:
    return discover_file_entities(ast.parse(src), module="demo", path="demo.py")


def test_default_provider_seeds_all_unknown_raw() -> None:
    entities = _entities("def a():\n    pass\ndef b():\n    pass\n")
    seeds = seed_function_taints(entities, ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider())
    assert set(seeds) == {"demo.a", "demo.b"}
    for seed in seeds.values():
        assert seed.body_taint == TaintState.UNKNOWN_RAW
        assert seed.return_taint == TaintState.UNKNOWN_RAW
        assert seed.source == "default"


class _StubProvider:
    """Opines on demo.a only; silent (None) on everything else."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult:
        if entity.qualname == "demo.a":
            return SeedResult(taint=FunctionTaint(body_taint=TaintState.EXTERNAL_RAW, return_taint=TaintState.GUARDED))
        return SeedResult(taint=None)


def test_provider_opinion_used_else_fallback() -> None:
    entities = _entities("def a():\n    pass\ndef b():\n    pass\n")
    seeds = seed_function_taints(entities, ctx=SeedContext(module="demo"), provider=_StubProvider())
    assert seeds["demo.a"] == FunctionSeed(
        qualname="demo.a",
        body_taint=TaintState.EXTERNAL_RAW,
        return_taint=TaintState.GUARDED,
        source="provider",
    )
    assert seeds["demo.b"].source == "default"
    assert seeds["demo.b"].body_taint == TaintState.UNKNOWN_RAW


def test_empty_entity_list() -> None:
    seeds = seed_function_taints([], ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider())
    assert seeds == {}


def test_methods_and_closures_all_seeded() -> None:
    src = "class C:\n    def m(self):\n        def inner():\n            pass\n"
    entities = _entities(src)
    seeds = seed_function_taints(entities, ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider())
    assert set(seeds) == {"demo.C.m", "demo.C.m.<locals>.inner"}
