# tests/unit/rust/test_mounts.py
"""Unit guards for the #[path] mount overlay (ADR-049 Amendment 8) — the behaviors the
vendored ``module_mounts`` corpus does NOT pin (mounted routes end-to-end live in
tests/conformance/test_loomweave_rust_qualname_parity.py::test_module_mounts):

* a mount CYCLE drops to the filesystem fallback (normative in the amendment text but
  un-corpused — these pin Wardline's deterministic resolution);
* a file tree-sitter cannot fully parse contributes NO mounts (fail-closed, matching
  the analyzer's refuse-to-half-analyze posture);
* a ``cfg_attr``-delivered ``path`` and a ``#[path]`` on an INLINE mod are not mounts;
* an un-mounted file routes byte-identically to ``rust_module_route`` (the overlay's
  default IS the fallback pin).
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust.mounts import build_mount_overlay  # noqa: E402
from wardline.rust.qualname import rust_module_route  # noqa: E402


def test_mount_cycle_drops_to_filesystem_fallback() -> None:
    # a.rs mounts b.rs; b.rs mounts a.rs — resolving either re-enters itself. The
    # amendment says cycles drop to the filesystem fallback; the corpus does not pin
    # WHICH link falls back, so this pins Wardline's resolution: the re-entered file
    # resolves by filesystem, and the chain stays deterministic from there.
    files = {
        "src/a.rs": '#[path = "b.rs"]\nmod from_a;\n',
        "src/b.rs": '#[path = "a.rs"]\nmod from_b;\n',
    }
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    # Resolving b walks b -> (declared in a) -> a -> (declared in b) -> b: the
    # RE-ENTERED file (the one being resolved) drops to its filesystem route, so each
    # file's chain terminates at itself. Order-independent: _resolve never consults
    # the memo mid-chain.
    assert overlay.logical_module_path("src/b.rs") == "demo.b.from_b.from_a"
    assert overlay.logical_module_path("src/a.rs") == "demo.a.from_a.from_b"


def test_self_mount_terminates() -> None:
    # Degenerate self-mount: a file mounting itself must terminate via the cycle rule.
    files = {"src/loop.rs": '#[path = "loop.rs"]\nmod me;\n'}
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    assert overlay.logical_module_path("src/loop.rs") == "demo.loop.me"


def test_unparseable_file_contributes_no_mounts() -> None:
    # Fail-closed: tree-sitter error-recovery in the declaring file drops its mounts —
    # no routing is derived from a file the analyzer refuses to analyze.
    files = {
        "src/lib.rs": '#[path = "impl_a.rs"]\nmod good; fn broken( {\n',
        "src/impl_a.rs": "pub fn a() {}\n",
    }
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    assert overlay.logical_module_path("src/impl_a.rs") == "demo.impl_a"


def test_cfg_attr_delivered_path_is_not_a_mount() -> None:
    # ADR-049 Amendment 8: only a LITERAL #[path] attribute is a mount — a
    # #[cfg_attr(pred, path = "…")] is invisible by dialect rule (no producer
    # evaluates cfg predicates); the target routes by filesystem.
    files = {
        "src/lib.rs": '#[cfg_attr(unix, path = "unix_impl.rs")]\nmod imp;\n',
        "src/unix_impl.rs": "pub fn u() {}\n",
    }
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    assert overlay.logical_module_path("src/unix_impl.rs") == "demo.unix_impl"


def test_path_on_inline_mod_is_not_a_mount() -> None:
    # The normative rule covers the DECL form (`mod name;`) only: a #[path] on an
    # inline `mod name { … }` mounts nothing, and the inline body still nests by name.
    files = {
        "src/lib.rs": '#[path = "elsewhere"]\nmod host { #[path = "real.rs"] mod imp; }\n',
        "src/host/real.rs": "pub fn r() {}\n",
    }
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    # The inner decl-mod mount still resolves against the BARE would-be directory
    # (src/host/), unaffected by the inline mod's ignored #[path].
    assert overlay.logical_module_path("src/host/real.rs") == "demo.host.imp"


def test_unmounted_file_matches_pure_filesystem_route() -> None:
    # The overlay's no-mount default MUST be byte-identical to rust_module_route
    # (the de-gapped `path_attr_known_gap` discipline).
    files = {"src/lib.rs": "pub fn f() {}\n"}
    overlay = build_mount_overlay(files, crate="demo", src_root="src")
    for file in ("src/lib.rs", "src/config.rs", "src/plugin/host.rs", "src/plugin/mod.rs"):
        assert overlay.logical_module_path(file) == rust_module_route(crate="demo", src_root="src", file=file)
