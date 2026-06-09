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
from wardline.rust.qualname import normalize_cfg_predicate, rust_module_route  # noqa: E402


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
    # The single top-level any()/all() case (the in-corpus shape) sorts its args. This
    # mirrors qualname.rs normalise_pred's NAIVE split(',') byte-for-byte — we do NOT
    # enshrine the deeper-nesting case, which the oracle deliberately mangles (the
    # contract is byte-equality with the oracle, not a "nicer" canonical form).
    assert normalize_cfg_predicate("(any(windows, unix))") == "any(unix,windows)"
    assert normalize_cfg_predicate("(all(unix, windows))") == "all(unix,windows)"


def test_positional_generics_are_rename_stable() -> None:
    # <T> and <U> render to the identical positional ($0) locator — a param rename
    # must not churn the qualname (ADR-049 De Bruijn rendering). No source-order ordinal
    # (ADR-049 amend, Option b).
    with_t = "struct Foo<T>(T);\nimpl<T> Foo<T> { fn get(&self) {} }\n"
    with_u = "struct Foo<U>(U);\nimpl<U> Foo<U> { fn get(&self) {} }\n"
    t = {e.qualname for e in discover_rust_entities(with_t, module="demo.m")}
    u = {e.qualname for e in discover_rust_entities(with_u, module="demo.m")}
    assert t == u == {"demo.m.Foo.impl#<$0>.get"}


def test_positional_generics_count_type_params_only() -> None:
    # syn generics.type_params() excludes lifetimes AND const params (ADR-049 amend);
    # only `T` counts. impl<'a, const N: usize, T> -> one positional $0.
    src = "struct Foo<T>(T);\nimpl<'a, const N: usize, T> Foo<T> { fn get(&self) {} }\n"
    quals = {e.qualname for e in discover_rust_entities(src, module="demo.m")}
    assert quals == {"demo.m.Foo.impl#<$0>.get"}


def test_trait_args_drop_lifetimes_and_bindings_and_omit_empty_brackets() -> None:
    # qualname.rs trait_generic_args keeps only Type/Const args (lifetimes AND
    # associated-type bindings dropped), and trait_impl omits <> when none survive.
    binding = "struct F;\nimpl Iterator<Item = u8> for F { fn next(&mut self) {} }\n"
    lifetime = "struct F;\nimpl<'a> MyTrait<'a> for F { fn m(&self) {} }\n"
    b = {e.qualname for e in discover_rust_entities(binding, module="m")}
    lt = {e.qualname for e in discover_rust_entities(lifetime, module="m")}
    assert b == {"m.F.impl[Iterator].next"}  # binding dropped, no brackets
    assert lt == {"m.F.impl[MyTrait].m"}  # lifetime dropped, no empty <>


def test_cfg_twin_inherent_impls_split_by_at_cfg() -> None:
    # Post-amendment the ordinal is gone, so a cfg-gated pair of same-signature inherent
    # impls would COLLIDE to one qualname (silent finding-masking) without the @cfg split.
    src = "struct Foo;\n#[cfg(unix)]\nimpl Foo { fn run(&self) {} }\n#[cfg(windows)]\nimpl Foo { fn run(&self) {} }\n"
    quals = sorted(e.qualname for e in discover_rust_entities(src, module="demo.m"))
    assert quals == ["demo.m.Foo.impl#<>@cfg(unix).run", "demo.m.Foo.impl#<>@cfg(windows).run"]
