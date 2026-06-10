"""The Rust index — the full ADR-049 entity surface + NodeId stamping.

Pins the entity-shape contract the corpus parity gate does not: that every emitted
entity carries a ``Location``, a ``NodeId``, and a ``parent`` containment link; that
closures and nested ``fn``s are NOT emitted (ADR-049 — the walk never descends a
``function_item`` body); that Wardline keeps its semantic ``function``/``method``
split in entity metadata while the qualname id-kind stays ``function`` for both; and
(Phase 1b) the leaf kinds, the merged ``impl`` entity, the corpus-pinned emit
ordering, the per-(kind, name) twin counter, and emission determinism.
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
    quals = {e.qualname for e in entities if e.kind in ("function", "method")}
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
    only = next(e for e in entities if e.kind == "function")
    assert NodeId(only.node_id) > NodeId(0)


# --------------------------------------------------------------------------- #
# Phase 1b producer surface: the full ten-kind ADR-049 emission (leaf kinds,
# the `impl` entity, module -> impl -> method containment, per-kind cfg twins,
# corpus-pinned emit ordering). Oracle: loomweave extract.rs (twin_counts
# :326-358; struct arm :397-400; inline-mod arm :436-439; trait arm :476-492 —
# trait BODIES are never walked) + the vendored qualnames_rust.json rows.
# --------------------------------------------------------------------------- #


def test_leaf_item_kinds_emitted_with_module_parent() -> None:
    # The five Phase-1b leaf kinds + macro_rules!, each at its source position with
    # qualname `<module>.<name>` and parent = the file module; the bare macro
    # INVOCATION emits nothing (corpus macro_invocation_generates_no_entity).
    src = (
        "pub enum Color { Red }\n"
        "pub trait Greet {}\n"
        "pub type Alias = u8;\n"
        "pub const LIMIT: u32 = 10;\n"
        'pub static NAME: &str = "x";\n'
        "macro_rules! make { () => { fn generated() {} } }\n"
        "make!();\n"
    )
    rows = [(e.qualname, e.kind, e.parent) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module", None),
        ("demo.m.Color", "enum", "demo.m"),
        ("demo.m.Greet", "trait", "demo.m"),
        ("demo.m.Alias", "type_alias", "demo.m"),
        ("demo.m.LIMIT", "const", "demo.m"),
        ("demo.m.NAME", "static", "demo.m"),
        ("demo.m.make", "macro", "demo.m"),
    ]


def test_impl_entity_rows_inherent_trait_and_cfg_forms() -> None:
    # The merged `impl` entity is a real row now: inherent `…impl#<>`, trait
    # `…impl[Display]`, and the @cfg-split twin forms (corpus inherent_method /
    # trait_method / trait_impl_cfg_twin).
    src = (
        "struct Foo;\n"
        "impl Foo { fn a(&self) {} }\n"
        "impl std::fmt::Display for Foo {"
        " fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) } }\n"
        "#[cfg(unix)]\nimpl Clone for Foo { fn clone(&self) -> Foo { Foo } }\n"
        "#[cfg(windows)]\nimpl Clone for Foo { fn clone(&self) -> Foo { Foo } }\n"
    )
    impls = [e.qualname for e in discover_rust_entities(src, module="demo.m") if e.kind == "impl"]
    assert impls == [
        "demo.m.Foo.impl#<>",
        "demo.m.Foo.impl[Display]",
        "demo.m.Foo.impl[Clone]@cfg(unix)",
        "demo.m.Foo.impl[Clone]@cfg(windows)",
    ]


def test_containment_parents_module_impl_method() -> None:
    # module -> impl -> method containment: a method's parent is the impl ENTITY
    # qualname; the impl's parent is the module; free items parent on the module.
    src = "fn free() {}\nstruct Foo;\nimpl Foo { fn bar(&self) {} }\n"
    by_q = {e.qualname: e for e in discover_rust_entities(src, module="demo.m")}
    assert by_q["demo.m"].parent is None
    assert by_q["demo.m.free"].parent == "demo.m"
    assert by_q["demo.m.Foo"].parent == "demo.m"
    assert by_q["demo.m.Foo.impl#<>"].parent == "demo.m"
    assert by_q["demo.m.Foo.impl#<>.bar"].parent == "demo.m.Foo.impl#<>"


def test_merged_impl_emitted_at_first_block_in_source_order() -> None:
    # Two same-key inherent blocks merge to ONE impl entity, emitted at the FIRST
    # contributing block (its location.line_start = block 1's line); both blocks'
    # methods follow in source order (corpus multiple_inherent_merge + oracle
    # emit_impl's seen_impl_ids first-block guard).
    src = "struct Foo;\nimpl Foo { fn a(&self) {} }\nimpl Foo { fn b(&self) {} }\n"
    entities = discover_rust_entities(src, module="demo.m")
    rows = [(e.qualname, e.kind) for e in entities]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.Foo", "struct"),
        ("demo.m.Foo.impl#<>", "impl"),
        ("demo.m.Foo.impl#<>.a", "method"),
        ("demo.m.Foo.impl#<>.b", "method"),
    ]
    (impl_entity,) = [e for e in entities if e.kind == "impl"]
    assert impl_entity.location.line_start == 2  # the FIRST contributing block


def test_file_module_entity_emitted_first_and_inline_mods_at_source_position() -> None:
    # Emit ordering (corpus nested_inline_mod / same_type_name_distinct_module_scopes):
    # the file-scope module entity comes FIRST, before any item; an inline `mod` entity
    # is emitted at its source position, BEFORE its members.
    src = "pub fn top() {}\nmod inner {\n    pub fn g() {}\n}\npub fn tail() {}\n"
    entities = discover_rust_entities(src, module="demo")
    rows = [(e.qualname, e.kind) for e in entities]
    assert rows == [
        ("demo", "module"),
        ("demo.top", "function"),
        ("demo.inner", "module"),
        ("demo.inner.g", "function"),
        ("demo.tail", "function"),
    ]
    by_q = {e.qualname: e for e in entities}
    assert by_q["demo.inner"].parent == "demo"
    assert by_q["demo.inner.g"].parent == "demo.inner"


def test_per_kind_twin_counting() -> None:
    # The twin counter is per-(kind, name) — extract.rs twin_counts. `fn S` and
    # `struct S` share a name but NOT a kind, so the cfg-gated fn is no twin and
    # gets NO @cfg suffix (the id's kind segment already separates them).
    src = "#[cfg(unix)]\nfn S() {}\nstruct S;\n"
    rows = {(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")}
    assert ("demo.m.S", "function") in rows
    assert ("demo.m.S", "struct") in rows
    assert not any("@cfg" in qual for qual, _ in rows)


def test_per_kind_twin_suffix_applies_within_a_leaf_kind() -> None:
    # Within one (kind, name) the @cfg suffix DOES split (corpus leaf_kind_cfg_twin).
    src = "#[cfg(unix)]\npub const LIMIT: u32 = 1;\n#[cfg(windows)]\npub const LIMIT: u32 = 2;\n"
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.LIMIT@cfg(unix)", "const"),
        ("demo.m.LIMIT@cfg(windows)", "const"),
    ]


def test_line_comment_interposition_does_not_detach_cfg() -> None:
    # Keystone-panel repro: a `//` comment between #[cfg] and its item. Comments are
    # token-stream-invisible to the oracle (syn never sees them — extract.rs
    # cfg_predicates operates on syn attributes, which attach across comments), so
    # the cfg must stay pending: both twins keep their @cfg discriminant, and there
    # is NO bare colliding `demo.m.f`.
    src = "#[cfg(unix)]\n// comment\npub fn f() {}\n#[cfg(windows)]\npub fn f() {}\n"
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.f@cfg(unix)", "function"),
        ("demo.m.f@cfg(windows)", "function"),
    ]


def test_doc_comment_interposition_does_not_detach_cfg() -> None:
    # The corpus row (cfg_attr_comment_interposition): a `///` doc comment IS a syn
    # attribute (#[doc = "..."], Meta::NameValue) but NOT a cfg, so it contributes
    # nothing to the discriminant — and in tree-sitter it is a plain line_comment
    # sibling that must not reset the pending cfg either.
    src = "#[cfg(unix)]\n// platform note\npub fn f() {}\n#[cfg(windows)]\n/// doc comment\npub fn f() {}\n"
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.f@cfg(unix)", "function"),
        ("demo.m.f@cfg(windows)", "function"),
    ]


def test_in_predicate_comment_is_token_invisible() -> None:
    # The corpus row (cfg_predicate_internal_comment): a /* */ comment INSIDE the
    # predicate never reaches the oracle's token stream (proc-macro2 drops comments),
    # so the discriminant renders from tokens only — comment stripped, any() args
    # sorted, whitespace gone.
    src = '#[cfg(any(unix, /* why */ windows))]\npub fn g() {}\n#[cfg(target_os = "macos")]\npub fn g() {}\n'
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.g@cfg(any(unix,windows))", "function"),
        ('demo.m.g@cfg(target_os="macos")', "function"),
    ]


def test_emission_is_deterministic() -> None:
    # Two runs over the same source produce byte-identical ordered emissions
    # (qualname, kind, parent, span) — the property the full-set ordered
    # conformance comparison and the identity freeze both lean on.
    src = (
        "pub enum Color { Red }\n"
        "struct Foo;\n"
        "impl Foo { fn a(&self) {} }\n"
        "impl Foo { fn b(&self) {} }\n"
        "mod inner {\n    pub fn g() {}\n}\n"
        "#[cfg(unix)]\nfn f() {}\n#[cfg(windows)]\nfn f() {}\n"
    )

    def run() -> list[tuple[str, str, str | None, int, int]]:
        return [
            (e.qualname, e.kind, e.parent, e.location.line_start, e.location.line_end)
            for e in discover_rust_entities(src, module="demo.m", path="m.rs")
        ]

    assert run() == run()


def test_identical_witness_twins_do_not_fire_stage_s() -> None:
    # ADR-049 Amendment 6, known residual BY DESIGN: coherence-illegal twins with the
    # SAME written self-type path carry identical witnesses — no witness can split
    # them, stage S stays cold, and the two blocks still MERGE onto one bare key
    # (upstream, `duplicate_ids()` is the alarm; un-corpused, pinned here).
    src = (
        "pub trait T { fn go(&self); }\n"
        "mod a { pub struct X; }\n"
        "impl T for a::X { fn go(&self){} }\n"
        "impl T for a::X { fn other(&self){} }\n"
    )
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [
        ("demo.m", "module"),
        ("demo.m.T", "trait"),
        ("demo.m.a", "module"),
        ("demo.m.a.X", "struct"),
        ("demo.m.X.impl[T]", "impl"),
        ("demo.m.X.impl[T].go", "method"),
        ("demo.m.X.impl[T].other", "method"),
    ]


def test_unnamed_const_skip_leaves_named_siblings_untouched() -> None:
    # ADR-049 Amendment 9 unit guard (the corpus pins the skip via ordered-equality;
    # this pins the SEMANTIC kind view too): `const _` emits nothing — no entity, no
    # twin-count participation — while named consts are unaffected.
    src = "pub const LIMIT: u32 = 10;\nconst _: () = assert!(true);\nconst _: () = assert!(true);\n"
    rows = [(e.qualname, e.kind) for e in discover_rust_entities(src, module="demo.m")]
    assert rows == [("demo.m", "module"), ("demo.m.LIMIT", "const")]
