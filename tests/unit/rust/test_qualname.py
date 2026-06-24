"""WP2: the Rust qualname dialect (Loomweave ADR-049).

The byte-for-byte entity-qualname obligation is pinned by the vendored corpus gate
(``tests/conformance/test_loomweave_rust_qualname_parity.py``). These focused tests
cover the two pieces the corpus exercises only thinly or not at all: ``rust_module_route``
(path -> dotted module) and the ``@cfg`` predicate normaliser (whitespace strip +
``any()/all()`` arg sort — ADR-049 specifies it but the slice-1 corpus only has bare
``unix``/``windows``), plus the rename-stability invariant as a direct assertion.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust.index import discover_rust_entities  # noqa: E402
from wardline.rust.parse import parse_rust  # noqa: E402
from wardline.rust.qualname import (  # noqa: E402
    RUST_ONTOLOGY_VERSION,
    RUST_PLUGIN_ID,
    cfg_discriminant,
    cfg_predicate_of,
    entity_id,
    normalize_cfg_predicate,
    rust_module_route,
)


def test_entity_id_maps_method_and_validates_kind() -> None:
    # entity_id mirrors loomweave's build_entity_id posture: `{plugin}:{kind}:{qualname}`,
    # Wardline's semantic `method` maps to the id-kind `function` HERE (callers never
    # pre-map), and a kind outside the ten-kind ADR-049 set raises.
    assert entity_id("function", "demo.m.f") == "rust:function:demo.m.f"
    assert entity_id("method", "demo.m.Foo.impl#<>.bar") == "rust:function:demo.m.Foo.impl#<>.bar"
    assert entity_id("impl", "demo.m.Foo.impl#<>") == "rust:impl:demo.m.Foo.impl#<>"
    assert entity_id("module", "demo.m") == "rust:module:demo.m"
    assert entity_id("type_alias", "demo.m.Alias") == "rust:type_alias:demo.m.Alias"
    with pytest.raises(ValueError, match="union"):
        entity_id("union", "demo.m.U")
    assert RUST_PLUGIN_ID == "rust"
    assert RUST_ONTOLOGY_VERSION == "0.4.0"


def _callable_quals(source: str, module: str) -> set[str]:
    """The CALLABLE qualnames of a source — these rendering tests pin method/fn
    qualname bytes; the full ten-kind emission surface is test_index.py's job."""
    return {e.qualname for e in discover_rust_entities(source, module=module) if e.kind in ("function", "method")}


def test_module_route_root_files_contribute_no_segment() -> None:
    assert rust_module_route(crate="demo", src_root="/p/src", file="/p/src/lib.rs") == "demo"
    assert rust_module_route(crate="demo", src_root="/p/src", file="/p/src/main.rs") == "demo"


def test_module_route_flat_and_nested_files() -> None:
    assert rust_module_route(crate="demo", src_root="/p/src", file="/p/src/config.rs") == "demo.config"
    assert rust_module_route(crate="demo", src_root="/p/src", file="/p/src/plugin/host.rs") == "demo.plugin.host"


def test_module_route_mod_rs_collapses_to_directory() -> None:
    assert rust_module_route(crate="demo", src_root="/p/src", file="/p/src/plugin/mod.rs") == "demo.plugin"


def test_normalize_cfg_strips_whitespace() -> None:
    assert normalize_cfg_predicate("( unix )") == "unix"
    assert normalize_cfg_predicate('(target_os = "linux")') == 'target_os="linux"'


def test_normalize_cfg_sorts_a_single_flat_any_all_like_the_oracle() -> None:
    # The single top-level any()/all() case (the in-corpus shape) sorts its args and
    # keeps the flat oracle bytes stable.
    assert normalize_cfg_predicate("(any(windows, unix))") == "any(unix,windows)"
    assert normalize_cfg_predicate("(all(unix, windows))") == "all(unix,windows)"


def test_normalize_cfg_sorts_nested_any_all_without_colliding() -> None:
    left = normalize_cfg_predicate("(any(all(a, a), all(c, b)))")
    right = normalize_cfg_predicate("(any(all(a, b), all(c, a)))")

    assert left == "any(all(a,a),all(b,c))"
    assert right == "any(all(a,b),all(a,c))"
    assert left != right


def test_normalize_cfg_predicate_escapes_reserved_chars() -> None:
    # % before : (order matters — injective, mirrors loomweave escape_reserved:
    # the introducer is encoded first so a literal source `%3A` cannot alias a
    # real escaped `:`; qualname.rs escape_reserved).
    assert normalize_cfg_predicate('feature = "a:b"') == 'feature="a%3Ab"'
    assert normalize_cfg_predicate('feature = "a%3Ab"') == 'feature="a%253Ab"'


def test_escape_happens_before_any_all_split() -> None:
    # escape applies to the whole stripped pred BEFORE arg sorting (oracle order:
    # qualname.rs normalise_pred — strip ws -> escape_reserved -> any()/all() sort).
    assert normalize_cfg_predicate('any(feature = "a:b", unix)') == 'any(feature="a%3Ab",unix)'


def test_cfg_discriminant_folds_all_predicates_sorted() -> None:
    # ALL predicates fold (each normalised, the set sorted, joined `&`) — mirrors
    # loomweave cfg_discriminant (qualname.rs); pinned upstream by stacked_cfg_twin.
    assert cfg_discriminant(["unix", 'feature = "a"']) == '@cfg(feature="a"&unix)'
    assert cfg_discriminant(['feature = "a"', "unix"]) == '@cfg(feature="a"&unix)'  # order-independent


def test_cfg_discriminant_normalizes_exactly_once() -> None:
    # raw input with a reserved char escapes ONCE (no double-escape through the
    # pipeline): index.py collects RAW predicates, cfg_discriminant is the single
    # normalisation point — the layering that prevents `a:b` -> `a%253Ab`.
    assert cfg_discriminant(['feature = "a:b"']) == '@cfg(feature="a%3Ab")'


def test_cfg_discriminant_rejects_empty_input() -> None:
    # An empty predicate list would render the meaningless `@cfg()` and silently
    # collide every "discriminated" twin onto it — a caller bug, surfaced loudly.
    with pytest.raises(ValueError, match="predicate"):
        cfg_discriminant([])


def test_cfg_predicate_of_returns_raw_unnormalized_text() -> None:
    # The collection-is-raw invariant (mirrors extract.rs cfg_predicates): the
    # returned predicate keeps its outer argument parens, source spacing, and the
    # UNESCAPED reserved `:` — cfg_discriminant is the single normalisation point
    # (normalising here too would double-escape `a:b` -> `a%253Ab`).
    tree = parse_rust('#[cfg(feature = "a:b")]\nfn f() {}\n')
    attr = next(c for c in tree.root_node.children if c.type == "attribute_item")
    assert cfg_predicate_of(attr) == '(feature = "a:b")'


def test_cfg_predicate_of_excludes_comment_tokens() -> None:
    # A /* */ comment inside the predicate is NOT part of the oracle's token stream
    # (proc-macro2 drops comments before cfg_predicates ever sees them), so the raw
    # collected text excludes the comment bytes — everything else stays raw
    # (the comment's surrounding source whitespace survives; normalize strips it).
    tree = parse_rust("#[cfg(any(unix, /* why */ windows))]\npub fn g() {}\n")
    attr = next(c for c in tree.root_node.children if c.type == "attribute_item")
    raw = cfg_predicate_of(attr)
    assert raw == "(any(unix,  windows))"
    assert normalize_cfg_predicate(raw) == "any(unix,windows)"


def test_positional_generics_are_rename_stable() -> None:
    # <T> and <U> render to the identical positional ($0) locator — a param rename
    # must not churn the qualname (ADR-049 De Bruijn rendering) — in BOTH the self-type
    # prefix (Foo<$0>) and the inherent #<$0> signature (self-type-args amendment, ADR-049
    # §2). No source-order ordinal (ADR-049 amend, Option b).
    with_t = "struct Foo<T>(T);\nimpl<T> Foo<T> { fn get(&self) {} }\n"
    with_u = "struct Foo<U>(U);\nimpl<U> Foo<U> { fn get(&self) {} }\n"
    t = _callable_quals(with_t, "demo.m")
    u = _callable_quals(with_u, "demo.m")
    assert t == u == {"demo.m.Foo<$0>.impl#<$0>.get"}


def test_positional_generics_count_type_params_only() -> None:
    # syn generics.type_params() excludes lifetimes AND const params (ADR-049 amend);
    # only `T` counts. impl<'a, const N: usize, T> -> one positional $0 in both prefix
    # (Foo<$0>) and signature (impl#<$0>).
    src = "struct Foo<T>(T);\nimpl<'a, const N: usize, T> Foo<T> { fn get(&self) {} }\n"
    quals = _callable_quals(src, "demo.m")
    assert quals == {"demo.m.Foo<$0>.impl#<$0>.get"}


def test_self_type_concrete_args_split_distinct_impls() -> None:
    # ADR-049 §2 self-type-args amendment: distinct CONCRETE instantiations get distinct
    # keys, so two like-named `get` methods do NOT collide/merge (the silent-data-loss
    # family the amendment closes). Mirrors corpus generic_self_inherent_concrete_args.
    src = "struct Foo<T>(T);\nimpl Foo<i32> { fn get(&self) {} }\nimpl Foo<u32> { fn get(&self) {} }\n"
    quals = _callable_quals(src, "demo.m")
    assert quals == {"demo.m.Foo<i32>.impl#<>.get", "demo.m.Foo<u32>.impl#<>.get"}


def test_nested_self_type_param_renders_literal_not_positional() -> None:
    # F2 nested-param rule: positional substitution is TOP-LEVEL only. A param nested
    # inside another self-type arg keeps its LITERAL text (Foo<Vec<T>>, NOT Foo<Vec<$0>>;
    # Foo<&T>, NOT Foo<&$0>). Loomweave owes a nested-param corpus row, so THIS is the
    # only guard against accidentally implementing recursive positional substitution.
    vec = "struct Foo<T>(T);\nimpl<T> Foo<Vec<T>> { fn get(&self) {} }\n"
    ref = "struct Foo<T>(T);\nimpl<T> Foo<&T> { fn get(&self) {} }\n"
    v = _callable_quals(vec, "demo.m")
    r = _callable_quals(ref, "demo.m")
    assert v == {"demo.m.Foo<Vec<T>>.impl#<$0>.get"}
    assert r == {"demo.m.Foo<&T>.impl#<$0>.get"}


def test_non_generic_self_type_renders_bare() -> None:
    # A non-generic self type renders the bare name (no empty brackets) — unchanged by
    # the self-type-args amendment.
    src = "struct Foo;\nimpl Foo { fn bar(&self) {} }\n"
    quals = _callable_quals(src, "demo.m")
    assert quals == {"demo.m.Foo.impl#<>.bar"}


def test_empty_turbofish_self_type_does_not_emit_empty_brackets() -> None:
    # `impl Foo<>` is malformed: tree-sitter error-recovers a blank generic arg (verified
    # has_errors=True, so the scan path gates it before index_entities). The PURE producer
    # must still not emit a `Foo<>` segment — Wardline filters the empty arg to bare `Foo`.
    # (Not asserted as oracle-convergence: whether syn accepts `impl Foo<>` at all is
    # unverified; either way neither producer emits a `Foo<>` entity for this input.)
    src = "struct Foo;\nimpl Foo<> { fn bar(&self) {} }\n"
    quals = _callable_quals(src, "demo.m")
    assert quals == {"demo.m.Foo.impl#<>.bar"}


def test_trait_args_drop_lifetimes_and_bindings_and_omit_empty_brackets() -> None:
    # qualname.rs trait_generic_args keeps only Type/Const args (lifetimes AND
    # associated-type bindings dropped), and trait_impl omits <> when none survive.
    binding = "struct F;\nimpl Iterator<Item = u8> for F { fn next(&mut self) {} }\n"
    lifetime = "struct F;\nimpl<'a> MyTrait<'a> for F { fn m(&self) {} }\n"
    b = _callable_quals(binding, "m")
    lt = _callable_quals(lifetime, "m")
    assert b == {"m.F.impl[Iterator].next"}  # binding dropped, no brackets
    assert lt == {"m.F.impl[MyTrait].m"}  # lifetime dropped, no empty <>


def test_cfg_twin_inherent_impls_split_by_at_cfg() -> None:
    # Post-amendment the ordinal is gone, so a cfg-gated pair of same-signature inherent
    # impls would COLLIDE to one qualname (silent finding-masking) without the @cfg split.
    src = "struct Foo;\n#[cfg(unix)]\nimpl Foo { fn run(&self) {} }\n#[cfg(windows)]\nimpl Foo { fn run(&self) {} }\n"
    quals = sorted(_callable_quals(src, "demo.m"))
    assert quals == ["demo.m.Foo.impl#<>@cfg(unix).run", "demo.m.Foo.impl#<>@cfg(windows).run"]
