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


def test_normalize_cfg_sorts_any_all_args_for_canonical_form() -> None:
    # ADR-049: any()/all() args are sorted so two source orderings of the same
    # predicate canonicalise to one locator. (Not in the slice-1 corpus; locked here.)
    assert normalize_cfg_predicate("(any(windows, unix))") == "any(unix,windows)"
    assert normalize_cfg_predicate("(all(unix, windows))") == "all(unix,windows)"
    assert normalize_cfg_predicate("(any(all(b, a), unix))") == "any(all(a,b),unix)"


def test_positional_generics_are_rename_stable() -> None:
    # <T> and <U> render to the identical positional ($0) locator — a param rename
    # must not churn the qualname (ADR-049 De Bruijn rendering).
    with_t = "struct Foo<T>(T);\nimpl<T> Foo<T> { fn get(&self) {} }\n"
    with_u = "struct Foo<U>(U);\nimpl<U> Foo<U> { fn get(&self) {} }\n"
    t = {e.qualname for e in discover_rust_entities(with_t, module="demo.m")}
    u = {e.qualname for e in discover_rust_entities(with_u, module="demo.m")}
    assert t == u == {"demo.m.Foo.impl#<$0>#0.get"}
