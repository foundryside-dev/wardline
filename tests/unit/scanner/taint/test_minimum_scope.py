# tests/unit/scanner/taint/test_minimum_scope.py
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.minimum_scope import (
    MinimumScopeProvenance,
    ProjectFileData,
    build_minimum_scope_edges,
    refine_minimum_scope_taints,
)

T = TaintState


def _file(src: str, module: str, path: str) -> ProjectFileData:
    tree = ast.parse(src)
    return ProjectFileData(
        entities=tuple(discover_file_entities(tree, module=module, path=path)),
        import_aliases=build_import_alias_map(tree, module),
        module_path=module,
    )


def test_edges_resolve_local_bare_call() -> None:
    src = "def caller():\n    callee()\ndef callee():\n    pass\n"
    edges, unresolved = build_minimum_scope_edges([_file(src, "m", "m.py")])
    assert edges["m.caller"] == frozenset({"m.callee"})
    assert unresolved["m.caller"] == 0


def test_edges_resolve_imported_project_function() -> None:
    caller = "from other import helper\ndef caller():\n    helper()\n"
    other = "def helper():\n    pass\n"
    files = [_file(caller, "main", "main.py"), _file(other, "other", "other.py")]
    edges, _ = build_minimum_scope_edges(files)
    assert edges["main.caller"] == frozenset({"other.helper"})


def test_unresolved_call_counted_not_edged() -> None:
    src = "def caller():\n    external_thing()\n"
    edges, unresolved = build_minimum_scope_edges([_file(src, "m", "m.py")])
    assert edges["m.caller"] == frozenset()
    assert unresolved["m.caller"] == 1


def test_one_hop_refines_via_provider_callee() -> None:
    # handler (ASSURED) calls fetch (provider-declared, returns EXTERNAL_RAW)
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.fetch"})},
        seed_taints={"m.handler": T.ASSURED, "m.fetch": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.fetch": "provider"},
        return_taints={"m.fetch": T.EXTERNAL_RAW},
        unresolved_counts={"m.handler": 0, "m.fetch": 0},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW
    assert isinstance(prov["m.handler"], MinimumScopeProvenance)
    assert prov["m.handler"].via_callee == "m.fetch"
    assert prov["m.handler"].source == "minimum_scope"


def test_two_hop_through_undecorated_intermediary() -> None:
    # handler → helper(default) → raw(provider, EXTERNAL_RAW)
    refined, _ = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.helper"}), "m.helper": frozenset({"m.raw"})},
        seed_taints={"m.handler": T.ASSURED, "m.helper": T.ASSURED, "m.raw": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.helper": "default", "m.raw": "provider"},
        return_taints={"m.raw": T.EXTERNAL_RAW},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW


def test_clean_different_family_callees_stay_clean() -> None:
    # Clean-direction (wardline-17b9ce2c70): handler (INTEGRAL) calls two
    # clean-but-DIFFERENT-family provider callees — validate (ASSURED) and lit
    # (INTEGRAL). The callee-set aggregation is the rank-meet least_trusted
    # (weakest-link), NOT taint_join: least_trusted(ASSURED, INTEGRAL) = ASSURED
    # (clean), so the handler stays clean. taint_join would clash them to
    # MIXED_RAW (rank 7, in the firing RAW_ZONE) — a PY-WL-101 false positive.
    refined, _prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.validate", "m.lit"})},
        seed_taints={"m.handler": T.INTEGRAL, "m.validate": T.ASSURED, "m.lit": T.INTEGRAL},
        seed_sources={"m.handler": "default", "m.validate": "provider", "m.lit": "provider"},
        return_taints={"m.validate": T.ASSURED, "m.lit": T.INTEGRAL},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.ASSURED  # clean, NOT MIXED_RAW


def test_one_raw_callee_among_clean_still_propagates() -> None:
    # Soundness companion: swap the INTEGRAL helper for a raw EXTERNAL_RAW
    # provider. least_trusted keeps the raw rank, so the handler is still raw
    # (would still fire) — the migration introduces no false negative.
    refined, _prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.validate", "m.raw"})},
        seed_taints={"m.handler": T.INTEGRAL, "m.validate": T.ASSURED, "m.raw": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.validate": "provider", "m.raw": "provider"},
        return_taints={"m.validate": T.ASSURED, "m.raw": T.EXTERNAL_RAW},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW  # raw still propagates


def test_three_hop_is_bounded_out() -> None:
    # handler → hop1 → hop2 → raw : one intermediary max, so handler stays ASSURED
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={
            "m.handler": frozenset({"m.hop1"}),
            "m.hop1": frozenset({"m.hop2"}),
            "m.hop2": frozenset({"m.raw"}),
        },
        seed_taints={
            "m.handler": T.ASSURED,
            "m.hop1": T.ASSURED,
            "m.hop2": T.ASSURED,
            "m.raw": T.EXTERNAL_RAW,
        },
        seed_sources={
            "m.handler": "default",
            "m.hop1": "default",
            "m.hop2": "default",
            "m.raw": "provider",
        },
        return_taints={"m.raw": T.EXTERNAL_RAW},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.ASSURED
    assert "m.handler" not in prov  # unchanged → no provenance


def test_self_call_is_ignored() -> None:
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.handler"})},
        seed_taints={"m.handler": T.ASSURED},
        seed_sources={"m.handler": "default"},
        return_taints={},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.ASSURED
    assert "m.handler" not in prov


def test_no_callees_leaves_taint_unchanged() -> None:
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.leaf"],
        edges={"m.leaf": frozenset()},
        seed_taints={"m.leaf": T.GUARDED},
        seed_sources={"m.leaf": "default"},
        return_taints={},
        unresolved_counts={},
    )
    assert refined["m.leaf"] == T.GUARDED
    assert "m.leaf" not in prov


def test_floor_clamp_never_increases_trust() -> None:
    # seed EXTERNAL_RAW(rank 5); callee INTEGRAL(rank 0) would be MORE trusted —
    # clamp keeps the less-trusted seed.
    refined, _ = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.pure"})},
        seed_taints={"m.handler": T.EXTERNAL_RAW, "m.pure": T.INTEGRAL},
        seed_sources={"m.handler": "default", "m.pure": "provider"},
        return_taints={"m.pure": T.INTEGRAL},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW


def test_provider_callee_without_return_taint_falls_back_to_seed() -> None:
    # A provider-anchored callee MISSING from return_taints: _anchor_or_seed must fall
    # back to the callee's seed taint (not KeyError). handler (INTEGRAL) calls fetch
    # (provider, seed EXTERNAL_RAW, absent from return_taints) -> handler demotes to
    # the seed EXTERNAL_RAW (weakest-link), never raising.
    refined, _prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.fetch"})},
        seed_taints={"m.handler": T.INTEGRAL, "m.fetch": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.fetch": "provider"},
        return_taints={},  # fetch absent -> _anchor_or_seed uses fetch's seed
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW


def test_target_function_without_seed_is_skipped() -> None:
    # A target function absent from seed_taints has no taint to refine: the loop must
    # skip it (no entry in the refined map), never raising.
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.present", "m.absent"],
        edges={"m.present": frozenset()},
        seed_taints={"m.present": T.GUARDED},  # m.absent has no seed
        seed_sources={"m.present": "default"},
        return_taints={},
        unresolved_counts={},
    )
    assert refined == {"m.present": T.GUARDED}
    assert "m.absent" not in refined
    assert "m.absent" not in prov
