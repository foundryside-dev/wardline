"""WP2: the minimal Rust index — ``function_item`` -> ``RustEntity`` + NodeId stamping.

Pins the entity-shape contract the corpus parity gate does not: that every emitted
entity carries a ``Location`` and a ``NodeId``, that closures and nested ``fn``s are
NOT emitted (ADR-049 — the walk never descends a ``function_item`` body), and that
Wardline keeps its semantic ``function``/``method`` split in entity metadata while the
qualname id-kind stays ``function`` for both.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.node_id import NodeId  # noqa: E402
from wardline.rust.index import RustEntity, discover_rust_entities  # noqa: E402

_SPECIMEN = (
    "pub fn top() {}\n"
    "struct Foo;\n"
    "impl Foo { fn bar(&self) {} }\n"
    "fn outer() {\n"
    "    fn inner() {}\n"  # nested fn -> NOT an entity
    "    let _g = || 1;\n"  # closure -> NOT an entity
    "}\n"
)


def test_emits_one_entity_per_callable_excluding_bodies() -> None:
    entities = discover_rust_entities(_SPECIMEN, module="demo.m")
    quals = {e.qualname for e in entities}
    assert quals == {"demo.m.top", "demo.m.Foo.impl#<>.bar", "demo.m.outer"}
    # the nested fn and the closure produced no entity of their own
    assert not any("inner" in q for q in quals)


def test_entities_carry_location_and_nodeid() -> None:
    entities = discover_rust_entities(_SPECIMEN, module="demo.m")
    for e in entities:
        assert isinstance(e, RustEntity)
        assert isinstance(e.node_id, int)  # NodeId is a NewType over int
        assert e.location.line_start is not None and e.location.line_start >= 1
    top = next(e for e in entities if e.qualname == "demo.m.top")
    assert top.location.line_start == 1


def test_semantic_kind_split_rides_metadata_not_the_qualname() -> None:
    # The id-kind in the qualname is `function` for both; the function/method
    # distinction is semantic metadata only (ADR-049 kind boundary).
    entities = {e.qualname: e for e in discover_rust_entities(_SPECIMEN, module="demo.m")}
    assert entities["demo.m.top"].kind == "function"
    assert entities["demo.m.Foo.impl#<>.bar"].kind == "method"


def test_stacked_cfg_twins_get_distinct_folded_suffixes() -> None:
    # ALL stacked #[cfg] attributes fold into the discriminant (loomweave extract.rs
    # cfg_predicates collects every cfg; folding only the FIRST/LAST would hand both
    # blocks the same suffix and silently merge them). Pinned upstream by the
    # stacked_cfg_twin corpus row.
    src = (
        "struct Foo;\n"
        '#[cfg(feature = "a")]\n#[cfg(unix)]\nimpl Foo { pub fn go(&self) {} }\n'
        '#[cfg(feature = "b")]\n#[cfg(unix)]\nimpl Foo { pub fn go(&self) {} }\n'
    )
    names = {e.qualname for e in discover_rust_entities(src, module="demo.m")}
    assert 'demo.m.Foo.impl#<>@cfg(feature="a"&unix).go' in names
    assert 'demo.m.Foo.impl#<>@cfg(feature="b"&unix).go' in names


def test_single_stacked_cfg_impl_without_twin_gets_no_suffix() -> None:
    # dialect: @cfg is a COLLISION discriminator — a lone stacked-cfg impl stays bare
    # (the suffix applies only when extract.rs's twin counter sees a path collision).
    src = '#[cfg(feature = "a")]\n#[cfg(unix)]\nstruct Foo;\nimpl Foo { pub fn go(&self) {} }\n'
    names = {e.qualname for e in discover_rust_entities(src, module="demo.m")}
    assert "demo.m.Foo.impl#<>.go" in names


def test_node_id_zero_is_the_root() -> None:
    # Sanity that the stamped NodeId comes from the shared mint authority (pre-order
    # from the root): the first function's id is well past 0 (root + items precede).
    entities = discover_rust_entities("fn only() {}\n", module="demo.m")
    (only,) = entities
    assert NodeId(only.node_id) > NodeId(0)
