"""Task 5: anchored ``imports``/``implements`` edges (changeset §6).

The shared corpus is entity-only, so the contract for edges is changeset
``docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`` §6 plus
the loomweave oracle source for what §6 leaves open (citations pinned per test):

* ``resolve.rs`` — ``Resolution`` (:10-20: Ambiguous always carries a REAL id, never
  null), ``resolve_use_path`` (:39-50: glob ``a::*`` → Ambiguous(in-project module id)
  else External), ``resolve_non_glob`` (:106-125: attempt-1 as-is, attempt-2 crate-root
  fallback ONLY for a bare single segment — a multi-segment miss stays External, the H5
  guard), ``resolve_ids`` (:127-139: 0 → External, 1 → Resolved, >1 → Ambiguous(first
  by sorted order)), ``normalize_path`` (:141-168: ``crate``/``self`` map to the crate;
  ``super::`` is a DELIBERATE 1b deferral upstream — see the super tests below for
  wardline's plan-locked extension).
* ``extract.rs`` — ``emit_use_edges``/``collect_use_leaves`` (:600-667: groups fan out,
  ``as`` aliases resolve the REAL path, a ``self`` group leaf → the prefix module, span
  = the whole ``use`` statement), the negative-impl bang guard + one-edge-per-impl-
  entity ``seen_impl_ids`` gate (:707-748), ``trait_path_for_lookup`` (:780-794: trait
  generic args STRIPPED for lookup).

Edges are anchored (byte spans) and resolved-or-dropped; ``confidence`` is only ever
``resolved`` or ``ambiguous`` — never ``inferred``.

Fixtures are real ``tmp_path`` crates with a ``Cargo.toml`` so the module routes come
from the SP2 whole-tree pass (``discover_crate_roots`` + ``rust_module_route``), not a
hand-typed module string.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust import qualname as q  # noqa: E402
from wardline.rust.crate_roots import discover_crate_roots  # noqa: E402
from wardline.rust.edges import (  # noqa: E402
    RustEdge,
    RustParsedFile,
    discover_rust_edges,
    index_rust_file,
)

_MANIFEST = '[package]\nname = "demo"\nversion = "0.1.0"\n'


def _parse_crate(tmp_path: Path, files: dict[str, str]) -> list[RustParsedFile]:
    """Write a real crate under ``tmp_path`` and produce the per-file parse products.

    Routes are REAL: ``discover_crate_roots`` reads the ``Cargo.toml`` package name and
    ``rust_module_route`` derives each file's module — the same SP2 pass the analyzer
    runs, so the edge tests exercise crate-prefixed cross-file resolution end to end.
    """
    crate = tmp_path / "app"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(_MANIFEST, encoding="utf-8")
    for rel, source in files.items():
        target = crate / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    roots = discover_crate_roots(tmp_path)
    parsed: list[RustParsedFile] = []
    for rel in files:
        file = (crate / rel).resolve()
        crate_dir = roots.crate_dir_for(file)
        crate_name = roots.crate_name_for(file)
        assert crate_dir is not None and crate_name is not None
        module = q.rust_module_route(crate=crate_name, src_root=str(crate_dir / "src"), file=str(file))
        parsed.append(index_rust_file(files[rel], module=module, path=rel))
    return parsed


def _edges(tmp_path: Path, files: dict[str, str]) -> list[RustEdge]:
    return discover_rust_edges(_parse_crate(tmp_path, files))


def _span(source: str, fragment: str) -> tuple[int, int]:
    start = source.encode("utf-8").find(fragment.encode("utf-8"))
    assert start >= 0, f"fixture fragment {fragment!r} not found"
    return start, start + len(fragment.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Base case: cross-file resolved imports + implements, spans pinned
# --------------------------------------------------------------------------- #


def test_base_two_file_resolved_imports_and_implements(tmp_path: Path) -> None:
    """One ``use crate::Greet`` + one ``impl Greet for Foo`` across two files.

    §6: ``imports`` from the enclosing MODULE entity, span = the use statement;
    ``implements`` from the trait-IMPL entity, span = the implemented-trait path node
    only (extract.rs:746 ``source_range_of(trait_path)``). The bare ``Greet`` trait
    name resolves via the crate-root-relative bare-segment fallback
    (resolve.rs:106-125 attempt 2).
    """
    foo_rs = "use crate::Greet;\nstruct Foo;\nimpl Greet for Foo {\n    fn hi(&self) {}\n}\n"
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub trait Greet {}\npub mod foo;\n",
            "src/foo.rs": foo_rs,
        },
    )
    imports = [e for e in edges if e.kind == "imports"]
    implements = [e for e in edges if e.kind == "implements"]
    assert len(imports) == 1
    assert len(implements) == 1

    imp = imports[0]
    assert imp.from_id == "rust:module:demo.foo"
    assert imp.to_id == "rust:trait:demo.Greet"
    assert imp.confidence == "resolved"
    assert (imp.source_byte_start, imp.source_byte_end) == _span(foo_rs, "use crate::Greet;")

    impl = implements[0]
    assert impl.from_id == "rust:impl:demo.foo.Foo.impl[Greet]"
    assert impl.to_id == "rust:trait:demo.Greet"
    assert impl.confidence == "resolved"
    # span anchors the implemented-trait path node ONLY — the `Greet` of the impl
    # header, not the whole impl block and not the use statement.
    start, end = impl.source_byte_start, impl.source_byte_end
    assert foo_rs.encode("utf-8")[start:end] == b"Greet"
    assert start > foo_rs.encode("utf-8").find(b"impl ")


def test_inherent_impl_emits_no_implements_edge(tmp_path: Path) -> None:
    edges = _edges(tmp_path, {"src/lib.rs": "struct Foo;\nimpl Foo {\n    fn go(&self) {}\n}\n"})
    assert [e for e in edges if e.kind == "implements"] == []


# --------------------------------------------------------------------------- #
# super:: resolution (wardline extension — plan-locked; upstream 1b defers)
# --------------------------------------------------------------------------- #


def test_super_and_nested_super_resolve_against_module_routes(tmp_path: Path) -> None:
    """``super::X`` from ``demo.a.b`` → ``demo.a.X``; ``super::super::Y`` → ``demo.Y``.

    Upstream 1b deliberately defers ``super::`` to External (resolve.rs:141-168: the
    defining-module path is not threaded through). Wardline DOES thread the enclosing
    module (it is the imports ``from_id``), so it implements the semantics that same
    oracle comment names as correct ("``super::a::S`` from module ``c.m.n`` means
    ``c.m.a.S``") — the plan-locked Design for what §6 leaves open.
    """
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub struct Y;\npub mod a;\n",
            "src/a.rs": "pub struct X;\npub mod b;\n",
            "src/a/b.rs": "use super::X;\nuse super::super::Y;\n",
        },
    )
    imports = {e.to_id: e for e in edges if e.from_id == "rust:module:demo.a.b"}
    assert set(imports) == {"rust:struct:demo.a.X", "rust:struct:demo.Y"}
    assert all(e.confidence == "resolved" for e in imports.values())


def test_super_past_crate_root_drops(tmp_path: Path) -> None:
    # `super::` at the crate root walks above the crate — resolved-or-dropped (D1).
    edges = _edges(tmp_path, {"src/lib.rs": "pub struct X;\nuse super::X;\n"})
    assert [e for e in edges if e.kind == "imports"] == []


def test_self_prefix_resolves_module_relative(tmp_path: Path) -> None:
    """``use self::B;`` in module ``demo.a`` → ``demo.a.B`` (module-relative).

    Interpreted §6 gap, pinned here: upstream 1b maps a leading ``self`` to the CRATE
    root (resolve.rs normalize_path — it lacks the defining module), which is wrong
    Rust semantics; wardline threads the enclosing module, so ``self::`` resolves
    module-relative (at the crate root the two agree byte-for-byte).
    """
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub mod a;\n",
            "src/a.rs": "pub struct B;\nuse self::B;\n",
        },
    )
    imports = [e for e in edges if e.kind == "imports"]
    assert [(e.from_id, e.to_id, e.confidence) for e in imports] == [
        ("rust:module:demo.a", "rust:struct:demo.a.B", "resolved")
    ]


# --------------------------------------------------------------------------- #
# Use-tree expansion: group fan-out, `as` alias, `self` group leaf
# --------------------------------------------------------------------------- #


def test_group_fanout_alias_real_path_and_self_leaf(tmp_path: Path) -> None:
    """``use crate::a::{self, B, C as Zed};`` → three edges from ONE statement.

    extract.rs:621-667 ``collect_use_leaves``: a Group fans out per branch; a Rename
    resolves the REAL path (``crate::a::C`` — the alias ``Zed`` is dropped); a ``self``
    group leaf terminates the PREFIX path unchanged (``crate::a`` → the module itself).
    All three share the one use-statement span.
    """
    lib_rs = "pub mod a;\nuse crate::a::{self, B, C as Zed};\n"
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": lib_rs,
            "src/a.rs": "pub struct B;\npub struct C;\n",
        },
    )
    imports = [e for e in edges if e.kind == "imports"]
    assert {(e.to_id, e.confidence) for e in imports} == {
        ("rust:module:demo.a", "resolved"),  # the `self` leaf → the prefix module
        ("rust:struct:demo.a.B", "resolved"),
        ("rust:struct:demo.a.C", "resolved"),  # real path, alias dropped
    }
    span = _span(lib_rs, "use crate::a::{self, B, C as Zed};")
    assert all((e.source_byte_start, e.source_byte_end) == span for e in imports)
    assert all(e.from_id == "rust:module:demo" for e in imports)
    assert not any("Zed" in e.to_id for e in imports)


# --------------------------------------------------------------------------- #
# Globs: in-project → ambiguous(module); external → dropped
# --------------------------------------------------------------------------- #


def test_glob_in_project_is_ambiguous_to_the_module(tmp_path: Path) -> None:
    """``use crate::a::*;`` → ONE ``ambiguous`` edge to the in-project module entity
    (resolve.rs:39-50: a glob can never be promoted to Resolved from syntax alone, but
    carries the REAL module id — never null)."""
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub mod a;\nuse crate::a::*;\n",
            "src/a.rs": "pub struct B;\npub struct C;\n",
        },
    )
    imports = [e for e in edges if e.kind == "imports"]
    assert [(e.to_id, e.confidence) for e in imports] == [("rust:module:demo.a", "ambiguous")]


def test_glob_external_is_dropped(tmp_path: Path) -> None:
    edges = _edges(tmp_path, {"src/lib.rs": "use std::collections::*;\n"})
    assert [e for e in edges if e.kind == "imports"] == []


# --------------------------------------------------------------------------- #
# Multi-kind ambiguity: deterministic first-by-sorted-order target
# --------------------------------------------------------------------------- #


def test_multi_kind_ambiguity_targets_first_id_by_sorted_order(tmp_path: Path) -> None:
    """``fn S`` + ``struct S`` legally share a qualname (value vs type namespace);
    ``use crate::S`` → ``ambiguous`` with ``to_id`` = FIRST entity id by sorted order
    (resolve.rs:127-139 ``resolve_ids`` — ``rust:function:…`` < ``rust:struct:…``)."""
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub fn S() {}\npub struct S;\npub mod b;\n",
            "src/b.rs": "use crate::S;\n",
        },
    )
    imports = [e for e in edges if e.kind == "imports"]
    assert [(e.to_id, e.confidence) for e in imports] == [("rust:function:demo.S", "ambiguous")]


# --------------------------------------------------------------------------- #
# External / unresolvable → dropped (resolved-or-dropped, D1)
# --------------------------------------------------------------------------- #


def test_external_use_is_dropped(tmp_path: Path) -> None:
    edges = _edges(tmp_path, {"src/lib.rs": "use std::fmt;\n"})
    assert [e for e in edges if e.kind == "imports"] == []


def test_multi_segment_miss_never_falls_back_to_crate_root(tmp_path: Path) -> None:
    """The bare-segment gate (resolve.rs:106-125): a MULTI-segment path that misses
    attempt 1 stays dropped — never re-prefixed with the crate (the H5 guard: an
    in-project ``mod serde`` must not capture an external ``use serde::Serialize``)."""
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": "pub mod serde;\nuse serde::Serialize;\n",
            "src/serde.rs": "pub struct Serialize;\n",
        },
    )
    # `serde::Serialize` attempt 1 looks up `serde.Serialize` (no crate prefix) — miss;
    # multi-segment, so NO crate-root fallback: dropped, NOT `demo.serde.Serialize`.
    assert [e for e in edges if e.to_id == "rust:struct:demo.serde.Serialize"] == []


def test_external_trait_impl_is_dropped(tmp_path: Path) -> None:
    edges = _edges(
        tmp_path,
        {"src/lib.rs": "use std::fmt;\nstruct Foo;\nimpl fmt::Display for Foo {}\n"},
    )
    assert [e for e in edges if e.kind == "implements"] == []


# --------------------------------------------------------------------------- #
# Trait lookup: generic args stripped; negative impls emit nothing
# --------------------------------------------------------------------------- #


def test_generic_trait_impl_resolves_with_args_stripped(tmp_path: Path) -> None:
    """``impl MyTrait<i32> for Foo`` resolves ``MyTrait`` — generic args STRIPPED for
    the lookup (extract.rs:780-794 ``trait_path_for_lookup``: the in-project trait
    entity is keyed on its bare ident). The span still anchors the full implemented-
    trait path node (``MyTrait<i32>``, syn Path spans include the args)."""
    lib_rs = "pub trait MyTrait<T> {}\nstruct Foo;\nimpl MyTrait<i32> for Foo {}\n"
    edges = _edges(tmp_path, {"src/lib.rs": lib_rs})
    implements = [e for e in edges if e.kind == "implements"]
    assert [(e.from_id, e.to_id, e.confidence) for e in implements] == [
        ("rust:impl:demo.Foo.impl[MyTrait<i32>]", "rust:trait:demo.MyTrait", "resolved")
    ]
    assert (implements[0].source_byte_start, implements[0].source_byte_end) == _span(lib_rs, "MyTrait<i32>")


def test_negative_impl_emits_no_implements_edge(tmp_path: Path) -> None:
    """``impl !Marker for Foo`` asserts NON-implementation → no (positive) edge
    (extract.rs:729-738: the bang guard; the impl ENTITY itself is still emitted)."""
    edges = _edges(
        tmp_path,
        {"src/lib.rs": "pub trait Marker {}\nstruct Foo;\nimpl !Marker for Foo {}\n"},
    )
    assert [e for e in edges if e.kind == "implements"] == []


# --------------------------------------------------------------------------- #
# Merged twin impl blocks → exactly ONE implements edge per impl entity
# --------------------------------------------------------------------------- #


def test_merged_twin_impl_blocks_emit_exactly_one_edge(tmp_path: Path) -> None:
    """Two same-key ``impl Greet for Foo`` blocks merge to ONE impl entity, and the
    ``implements`` edge is emitted once per impl ENTITY (extract.rs:707-727
    ``seen_impl_ids`` — the second block only appends methods)."""
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": (
                "pub trait Greet {}\n"
                "struct Foo;\n"
                "impl Greet for Foo {\n    fn a(&self) {}\n}\n"
                "impl Greet for Foo {\n    fn b(&self) {}\n}\n"
            )
        },
    )
    implements = [e for e in edges if e.kind == "implements"]
    assert [(e.from_id, e.to_id) for e in implements] == [("rust:impl:demo.Foo.impl[Greet]", "rust:trait:demo.Greet")]


# --------------------------------------------------------------------------- #
# Enclosing-module from_id: inline mods; non-module scopes emit nothing
# --------------------------------------------------------------------------- #


def test_use_inside_inline_mod_is_from_that_mod_entity(tmp_path: Path) -> None:
    edges = _edges(
        tmp_path,
        {"src/lib.rs": "pub trait Greet {}\nmod inner {\n    use crate::Greet;\n}\n"},
    )
    imports = [e for e in edges if e.kind == "imports"]
    assert [(e.from_id, e.to_id) for e in imports] == [("rust:module:demo.inner", "rust:trait:demo.Greet")]


def test_use_inside_a_function_body_emits_nothing(tmp_path: Path) -> None:
    # §6: "one per FILE-SCOPE use leaf" — the oracle walks module item lists only
    # (a fn-body use is not a module property; extract.rs never visits it).
    edges = _edges(
        tmp_path,
        {"src/lib.rs": "pub trait Greet {}\nfn f() {\n    use crate::Greet;\n}\n"},
    )
    assert [e for e in edges if e.kind == "imports"] == []


# --------------------------------------------------------------------------- #
# Confidence is never `inferred` (anchored edges, ADR-026 decision 3)
# --------------------------------------------------------------------------- #


def test_confidence_is_never_inferred(tmp_path: Path) -> None:
    edges = _edges(
        tmp_path,
        {
            "src/lib.rs": (
                "pub trait Greet {}\n"
                "pub mod a;\n"
                "use crate::a::*;\n"  # ambiguous
                "use crate::Greet;\n"  # resolved
                "use std::fmt;\n"  # dropped
                "struct Foo;\n"
                "impl Greet for Foo {}\n"  # resolved
            ),
            "src/a.rs": "pub struct B;\n",
        },
    )
    assert edges, "fixture must produce edges"
    assert {e.confidence for e in edges} <= {"resolved", "ambiguous"}
    assert {e.kind for e in edges} == {"imports", "implements"}
