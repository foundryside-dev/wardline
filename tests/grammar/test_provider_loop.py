"""Track 2 T2.2 — the provider's generic boundary-type loop.

The litmus: a CUSTOM boundary type (from the agent's own module, not
``wardline.decorators``) seeds via the same loop the builtins ride; an unprovable
custom boundary surfaces a signal, while the same shape on a BUILTIN stays silent
(oracle-preserving). Also pins grammar-aware ``fingerprint()``.
"""

from __future__ import annotations

import ast

from wardline.core.registry import REGISTRY_VERSION
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint, SeedContext

_CUSTOM = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
    seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
    builtin=False,
)


def _entity(src: str):  # noqa: ANN202
    tree = ast.parse(src)
    return discover_file_entities(tree, module="m", path="m.py")[0]


def _ctx() -> SeedContext:
    # myproj resolves to itself (a real import alias map would carry this).
    return SeedContext(module="m", alias_map={"myproj": "myproj"})


def test_custom_boundary_type_seeds_via_loop() -> None:
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM,))
    ent = _entity("@myproj.trust.sanitized(to_level='GUARDED')\ndef f(p):\n    return p\n")
    res = provider.taint_for(ent, _ctx())
    assert res.taint == FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.GUARDED)
    assert res.unprovable_boundaries == ()


def test_unprovable_custom_boundary_signals() -> None:
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM,))
    # to_level is a bare Name (CFG) — not statically readable -> fail-closed + signal.
    ent = _entity("@myproj.trust.sanitized(to_level=CFG)\ndef f(p):\n    return p\n")
    res = provider.taint_for(ent, _ctx())
    assert res.taint is None
    assert res.unprovable_boundaries == ("sanitized",)


def test_provable_decorator_does_not_silently_override_unprovable_custom() -> None:
    # Finding 1 (review): a function stacking a PROVABLE builtin + an unprovable
    # custom must NOT be silently over-trusted by the provable one. The meet is
    # dragged to the fail-closed UNKNOWN_RAW AND the unprovable name is reported.
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM,))
    ent = _entity(
        "from wardline.decorators import trusted\nimport myproj.trust\n"
        "@trusted(level='ASSURED')\n@myproj.trust.sanitized(to_level=CFG)\ndef g(p):\n    return p\n"
    )
    alias_map = {"trusted": "wardline.decorators.trusted", "myproj": "myproj"}
    res = provider.taint_for(ent, SeedContext(module="m", alias_map=alias_map))
    assert res.taint == FunctionTaint(TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_RAW)  # NOT ASSURED
    assert res.unprovable_boundaries == ("sanitized",)


def test_multiple_unprovable_customs_all_reported() -> None:
    # Finding 2 (review): two distinct unprovable customs on one function are BOTH
    # named (no silent truncation of the second).
    second = BoundaryType(
        "scrubbed",
        "myproj.trust",
        1,
        (LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),
        lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM, second))
    ent = _entity(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=A)\n"
        "@myproj.trust.scrubbed(to_level=B)\ndef g(p):\n    return p\n"
    )
    res = provider.taint_for(ent, SeedContext(module="m", alias_map={"myproj": "myproj"}))
    assert res.taint is None
    assert set(res.unprovable_boundaries) == {"sanitized", "scrubbed"}


def test_builtin_matches_submodule_import_path() -> None:
    # Regression (the corpus oracle missed this): `from wardline.decorators.trust
    # import trust_boundary` resolves to the SUBMODULE FQN
    # wardline.decorators.trust.trust_boundary — the pre-Track-2 matcher accepted it
    # (prefix + last-segment rule), so the loop must too.
    provider = DecoratorTaintSourceProvider()  # builtins only
    ent = _entity(
        "from wardline.decorators.trust import trust_boundary\n"
        "@trust_boundary(to_level=TaintState.GUARDED)\ndef v(x):\n    return x\n"
    )
    alias_map = {
        "trust_boundary": "wardline.decorators.trust.trust_boundary",
        "TaintState": "wardline.core.taints.TaintState",
    }
    res = provider.taint_for(ent, SeedContext(module="m", alias_map=alias_map))
    assert res.taint == FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.GUARDED)


def test_unprovable_builtin_does_not_signal() -> None:
    # Oracle-preserving twin: an unreadable BUILTIN level stays silent (no signal).
    provider = DecoratorTaintSourceProvider()  # builtins only
    ent = _entity(
        "from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\ndef f(p):\n    return p\n"
    )
    alias_map = {"trust_boundary": "wardline.decorators.trust_boundary"}
    res = provider.taint_for(ent, SeedContext(module="m", alias_map=alias_map))
    assert res.taint is None
    assert res.unprovable_boundaries == ()


def test_fingerprint_builtin_is_legacy_string() -> None:
    # Builtin-only grammar must keep TODAY's exact fingerprint (cache/baseline stability).
    assert DecoratorTaintSourceProvider().fingerprint() == f"decorator-vocab:{REGISTRY_VERSION}"


def test_fingerprint_custom_grammar_is_distinct_and_stable() -> None:
    p1 = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM,))
    p2 = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (_CUSTOM,))
    builtin_fp = DecoratorTaintSourceProvider().fingerprint()
    assert p1.fingerprint() != builtin_fp  # distinct from builtins
    assert p1.fingerprint() == p2.fingerprint()  # stable across equal grammars
