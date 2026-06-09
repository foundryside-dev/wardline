"""WP3: the Rust trust provider — `/// @trusted(level=...)` doc-comment markers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.taints import TaintState  # noqa: E402
from wardline.rust import vocabulary  # noqa: E402
from wardline.rust.parse import parse_rust  # noqa: E402
from wardline.rust.provider import RustTrustProvider, rust_provider_fingerprint  # noqa: E402

if TYPE_CHECKING:
    from tree_sitter import Node


def _first_fn(source: str) -> Node:
    tree = parse_rust(source)
    fn = next(c for c in tree.root_node.children if c.type == "function_item")
    return fn


def test_trusted_marker_seeds_declared_trust() -> None:
    fn = _first_fn("/// @trusted(level=ASSURED)\nfn f() {}\n")
    seed = RustTrustProvider().taint_for(fn)
    assert seed is not None
    assert seed.body_taint is TaintState.ASSURED
    assert seed.return_taint is TaintState.ASSURED


def test_trusted_marker_accepts_guarded() -> None:
    fn = _first_fn("/// @trusted(level=GUARDED)\npub fn f() {}\n")
    seed = RustTrustProvider().taint_for(fn)
    assert seed is not None and seed.body_taint is TaintState.GUARDED


def test_marker_survives_an_interleaved_cfg_attribute() -> None:
    # The marker may sit between a #[cfg] attribute and the fn (both are preceding
    # siblings); the provider must still find it.
    fn = _first_fn("#[cfg(unix)]\n/// @trusted(level=ASSURED)\nfn f() {}\n")
    seed = RustTrustProvider().taint_for(fn)
    assert seed is not None and seed.body_taint is TaintState.ASSURED


def test_unmarked_fn_has_no_opinion_fail_closed() -> None:
    # No marker -> None (the L1 seeder turns this into the fail-closed UNKNOWN_RAW
    # default, source='default').
    fn = _first_fn("fn f() {}\n")
    assert RustTrustProvider().taint_for(fn) is None


def test_prose_mention_of_trusted_does_not_match() -> None:
    fn = _first_fn("/// see the @trusted convention in the docs\nfn f() {}\n")
    assert RustTrustProvider().taint_for(fn) is None


def test_malformed_level_is_surfaced_not_silently_ignored() -> None:
    fn = _first_fn("/// @trusted(level=BOGUS)\nfn f() {}\n")
    with pytest.raises(ValueError, match="level"):
        RustTrustProvider().taint_for(fn)


def test_fingerprint_embeds_version_and_changes_on_bump() -> None:
    prov = RustTrustProvider()
    assert prov.fingerprint() == rust_provider_fingerprint(vocabulary.RUST_TAINT_VERSION)
    assert prov.fingerprint() == f"rust-vocab:{vocabulary.RUST_TAINT_VERSION}"
    # A version bump must change the fingerprint (closes the cache-version gap).
    assert rust_provider_fingerprint(vocabulary.RUST_TAINT_VERSION) != rust_provider_fingerprint(
        vocabulary.RUST_TAINT_VERSION + 1
    )
