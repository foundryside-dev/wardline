# tests/conformance/test_loomweave_rust_qualname_parity.py
"""Pin Wardline's *Rust* qualname producer against Loomweave's normative corpus.

For Rust, **Loomweave is authoritative** (its whole-tree ``syn`` extractor is the
oracle; the dialect is fixed by Loomweave ADR-049). This INVERTS the Python
arrangement: Wardline *vendors* ``qualnames_rust.json`` and reproduces its
``expected`` qualnames byte-for-byte from the tree-sitter frontend — Wardline is
the *second producer*, it MINTS the same locator string and never parses it.

Provenance — re-vendor when Loomweave bumps the corpus:
    source: loomweave  rc4  @ 113c2e2217131fe67f7edb9ea42a2f9eeb48642b
            (fixtures/qualnames_rust.json, blob d81fb97544ed1c26b50198556022662e5387a130,
            extractor-generated, locked by
            crates/loomweave-plugin-rust/tests/qualname_conformance.rs)
    vendored byte-identical to tests/conformance/qualnames_rust.json (2026-06-11,
    the Amendments 4-9 batch re-vendor — one blob covers the 4-5 AND 6-9 changeset
    letters; 49 entity rows + 6 module_route rows + the NEW module_mounts section,
    8 rows).

Drift alarm (two layers — wardline-868908944b):
    1. Byte-pin (default suite): ``UPSTREAM_BLOB_SHA`` below pins the vendored file's
       git blob hash. ANY byte change to the vendored copy fails loudly — re-vendors
       are deliberate, atomic, and update the constant in the same commit.
    2. Live recheck (opt-in, ``-m loomweave_drift``): byte-compares the vendored copy
       against the sibling checkout (``WARDLINE_LOOMWEAVE_REPO``, default
       ``/home/john/loomweave``); skips when the checkout is absent (CI).

RE-VENDOR PROCEDURE — a RELEASE-GATE item (run ``pytest -m loomweave_drift -v``
before every release; on drift, or on any deliberate corpus bump upstream):
    1. ``cp $WARDLINE_LOOMWEAVE_REPO/fixtures/qualnames_rust.json
       tests/conformance/qualnames_rust.json`` — byte-verbatim. NEVER hand-edit the
       vendored copy; the upstream extractor + its cargo gate are the only authors.
    2. Update ``UPSTREAM_BLOB_SHA`` to ``git hash-object tests/conformance/qualnames_rust.json``
       and refresh the provenance lines above (source commit + blob) — all in the
       SAME commit as the new bytes.
    3. Re-run conformance (``pytest tests/conformance -q``) and CONFORM the producer
       until byte-green — fix ``wardline.rust.*``, never weaken the comparison.
    The cab95a1 re-vendor (keystone-panel rows) adds TWO cases pinning syn's
    token-stream comment semantics: ``cfg_attr_comment_interposition`` (a ``//`` or
    ``///`` comment between ``#[cfg]`` and its item never detaches the cfg — both
    twins keep their ``@cfg`` discriminant) and ``cfg_predicate_internal_comment``
    (a ``/* ... */`` inside the predicate is invisible to the token stream —
    ``any(unix, /* why */ windows)`` renders ``any(unix,windows)``).
    The prior a209fc7 re-vendor (rust-sp2 sprint, Task 1 upstream) added FIVE cases:
    ``generic_self_nested_param`` (the F2 nested-param trip-wire — the unit-only
    guard now has its corpus row), ``leaf_item_kinds`` (enum/trait/type_alias/
    const/static), ``stacked_cfg_twin`` (ALL #[cfg] predicates folded — normalised,
    sorted, ``&``-joined), ``cfg_escape_reserved_char`` (injective escape ``%``->``%25``
    then ``:``->``%3A``, applied to the whitespace-stripped predicate BEFORE any
    any()/all() arg sort), and ``leaf_kind_cfg_twin`` (per-(kind, name) twin counter).
    NOTE: this is the **ADR-049 amendment 3 (self-type generic args)** corpus, layered on
    amendment Option b. The impl ``<Type>`` segment now carries the self type's CONCRETE
    generic args (``Foo<i32>`` vs ``Foo<u32>`` are distinct keys; the impl's own top-level
    declared params render positionally, ``Foo<$0>``) — closing a silent-merge data-loss
    family where like-named methods on different instantiations collided. The 8f4f85f
    re-vendor changes 2 rows (``positional_generic_param``/``_renamed``:
    ``Foo.impl#<$0>`` -> ``Foo<$0>.impl#<$0>``) and adds 3 (``generic_self_inherent_concrete_args``,
    ``generic_self_trait_concrete_args``, ``generic_self_same_concrete_two_blocks_merge``).
    Still present from prior amendments: the dropped inherent ordinal (``Foo.impl#<>.bar``,
    not ``impl#<>#0.bar``), same-key inherent merge, and the two cfg-twin-on-impl trip-wires
    (``inherent_impl_cfg_twin`` / ``trait_impl_cfg_twin``). KNOWN GAP — the F2 nested-param
    rule (``impl<T> Foo<Vec<T>>`` -> literal ``Foo<Vec<T>>``, NOT recursive ``Foo<Vec<$0>>``)
    has NO corpus row yet (Loomweave owes one); it is guarded only by
    tests/unit/rust/test_qualname.py::test_nested_self_type_param_renders_literal_not_positional.
    ⚠️ The earlier federation handshake doc
    (loomweave docs/federation/2026-06-09-rust-qualname-dialect-response.md) still
    describes the *old* ordinal form — left intact as history, SUPERSEDED by the Phase 1b
    change-set (docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md,
    amended for amendment 3), which is the authoritative description of this corpus. Where
    any doc and the live extractor + this corpus diverge, the extractor + corpus are the oracle.
    The 113c2e2 re-vendor (ADR-049 Amendments 4-9, ONE batch covering both the 4-5 and
    6-9 changeset letters) adds 14 entity rows + the module_mounts section and de-gaps
    `path_attr_known_gap` (now a FALLBACK pin of the unchanged pure-filesystem route):
    **Amendments 4+5** — generic-arg escape pipeline (escape_reserved(strip_ws(arg)) at
    every concrete-arg + non-Type::Path self-type render site) and method-level @cfg on
    cfg-twin impl fns keyed on the FINAL impl qualname. **Amendments 6+7** — the
    residual-collision LADDER (@cfg -> stage S self-type written path -> stage T trait
    written path -> method-@cfg), twin-gated end to end (rows self_type_path_* /
    trait_path_* / impl_ladder_* / method_cfg_twin_in_s_fired_merged_blocks).
    **Amendment 8** — the #[path] mount overlay (module_mounts section, mounted routes
    end-to-end incl. chains, macro-invisibility, cfg-twin composition, R5 first-wins).
    **Amendment 9** — `const _` skip-emission (unnamed_const_skip pins the skip as an
    ABSENT expected row; the ordered-equality gate self-enforces it).

Status: the Rust frontend (``wardline.rust.*``) now EXISTS (slice-1 WP2 landed), so
the *producer-parity* tests below run live (``_rust_producer`` resolves
``wardline.rust.index`` — they no longer skip). The *structural* self-tests also run
and catch a malformed / stale re-vendor. SP2 rows assert for real (the whole-tree
crate-root pass landed — ``wardline.rust.crate_roots``); no xfail tier remains.

The comparison rule — GRADUATED (Phase 1b): Wardline now emits the FULL ten-kind
ADR-049 surface (changeset §7 rule 1 for full-surface producers), so the gate is
**ordered-list equality of `(qualname, kind)` pairs** against the corpus
``expected`` — exactly loomweave's own ordered conformance gate. Wardline's
semantic ``method`` maps to the id-kind ``function`` (the only mapping applied);
``module`` rows are compared like every other row AND the ``module_route``
section separately validates the file->module routing. The corpus
``_consumer_comparison`` subset rule (set-equality over function rows) remains
valid for function-only CONSUMERS; Wardline is no longer one.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

_CORPUS_PATH = Path(__file__).parent / "qualnames_rust.json"
_CORPUS: dict[str, Any] = json.loads(_CORPUS_PATH.read_text("utf-8"))

# The git blob hash of the vendored corpus as committed upstream (loomweave rc4
# @ 113c2e2217131fe67f7edb9ea42a2f9eeb48642b). Re-vendors update this constant in
# the SAME commit as the new bytes — see the RE-VENDOR PROCEDURE in the header.
UPSTREAM_BLOB_SHA = "d81fb97544ed1c26b50198556022662e5387a130"

_KNOWN_TIERS = {"slice-1", "sp2"}
# The a209fc7 corpus carries the FULL ten-kind ADR-049 surface (leaf_item_kinds /
# leaf_kind_cfg_twin pin enum/trait/type_alias/const/static; macro + impl were already
# present), and Wardline now compares its FULL ordered emission against it (Phase 1b
# graduation). The kinds must be *known* so test_expected_kinds_are_known stays a real
# guard, not a false failure.
_KNOWN_KINDS = {
    "module",
    "struct",
    "function",
    "enum",
    "trait",
    "type_alias",
    "const",
    "static",
    "macro",
    "impl",
}


def _expected_all_pairs(case: dict[str, Any]) -> list[tuple[str, str]]:
    """The full-surface obligation: the case's ``expected`` rows as an ORDERED list of
    ``(qualname, kind)`` pairs — order is part of the contract (loomweave's own gate
    compares the emission list in order)."""
    return [(row["qualname"], row["kind"]) for row in case["expected"]]


# --------------------------------------------------------------------------- #
# Structural self-tests — run NOW (no frontend / tree-sitter needed). These pin
# the vendored corpus so a malformed or stale re-vendor fails loudly in CI.
# --------------------------------------------------------------------------- #


def test_corpus_shape() -> None:
    for key in ("_doc", "_dialect_summary", "_consumer_comparison", "module_route", "module_mounts", "entities"):
        assert key in _CORPUS, f"vendored corpus is missing the '{key}' section"
    assert _CORPUS["entities"], "corpus has no entity cases"
    assert _CORPUS["module_route"], "corpus has no module_route cases"
    assert _CORPUS["module_mounts"], "corpus has no module_mounts cases (ADR-049 Amendment 8)"
    assert _CORPUS["_consumer_comparison"].strip(), "the comparison contract must travel with the data"


def test_reproducibility_tiers_are_known() -> None:
    # Guard: a resync that introduces a new tier would silently bypass the
    # slice-1-runs / sp2-xfails gating below.
    tiers = {c["reproducibility"] for c in _CORPUS["entities"]}
    tiers |= {r["reproducibility"] for r in _CORPUS["module_route"]}
    tiers |= {r["reproducibility"] for r in _CORPUS["module_mounts"]}
    assert tiers <= _KNOWN_TIERS, f"unhandled reproducibility tiers: {tiers - _KNOWN_TIERS}"


def test_expected_kinds_are_known() -> None:
    # Guard: a new id-kind would silently fall through the function/struct/module
    # comparison rule.
    kinds = {row["kind"] for c in _CORPUS["entities"] for row in c["expected"]}
    assert kinds <= _KNOWN_KINDS, f"unhandled expected kinds: {kinds - _KNOWN_KINDS}"


def test_corpus_exercises_functions() -> None:
    # Non-vacuity at the corpus level: at least one function qualname exists to
    # reproduce (a corpus of only struct/module rows would make the gate empty).
    assert any(row["kind"] == "function" for c in _CORPUS["entities"] for row in c["expected"]), (
        "corpus exercises no function qualnames — the producer gate would be vacuous"
    )


# --------------------------------------------------------------------------- #
# Corpus drift alarm (wardline-868908944b) — layer 1 runs in the default suite;
# layer 2 is the opt-in live recheck against the sibling checkout.
# --------------------------------------------------------------------------- #


def test_vendored_corpus_matches_upstream_blob_pin() -> None:
    """Layer 1: the vendored corpus byte-pins to the upstream git blob hash."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = _CORPUS_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored corpus changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit "
        "and re-run conformance; if not, someone edited the vendored copy (forbidden — "
        "the upstream extractor is the only author; see the RE-VENDOR PROCEDURE in this "
        "module's header)"
    )


@pytest.mark.loomweave_drift
def test_vendored_corpus_matches_live_sibling_checkout() -> None:
    """Layer 2 (opt-in, ``-m loomweave_drift``): the sibling loomweave checkout's
    fixture must be byte-identical to the vendored copy — the release-gate drift
    alarm. Absent checkout (CI) skips; drift FAILS."""
    repo = Path(os.environ.get("WARDLINE_LOOMWEAVE_REPO", "/home/john/loomweave"))
    upstream = repo / "fixtures" / "qualnames_rust.json"
    if not upstream.is_file():
        pytest.skip(f"no loomweave sibling checkout at {repo} (override via WARDLINE_LOOMWEAVE_REPO)")
    if upstream.read_bytes() != _CORPUS_PATH.read_bytes():
        pytest.fail(
            f"upstream {upstream} has drifted from the vendored tests/conformance/qualnames_rust.json — "
            "re-vendor + conform: follow the RE-VENDOR PROCEDURE in this module's header "
            "(byte-verbatim copy, bump UPSTREAM_BLOB_SHA in the same commit, re-run conformance)"
        )


# --------------------------------------------------------------------------- #
# Producer-parity tests — SKIP until the Rust frontend exists (slice-1 WP2).
# --------------------------------------------------------------------------- #


def _rust_producer() -> tuple[Any, Any]:
    """Resolve the Rust frontend producer, or skip. WP2 wires the real API here;
    the corpus then becomes a live byte-for-byte parity gate.

    Expected slice-1 surface (pinned in the plan's WP2):
      - ``wardline.rust.index.discover_rust_entities(source: str, *, module: str)
        -> Sequence[RustEntity]`` (parses internally; entities carry ``.qualname``;
        the case supplies ``module`` directly — the scan path derives it from
        Cargo.toml crate roots, ``wardline.rust.crate_roots``);
      - ``wardline.rust.qualname.rust_module_route(*, crate: str, src_root: str,
        file: str) -> str``.

    Imported dynamically (``importlib``) so the type-checker does not statically
    resolve a module that does not exist until WP2 lands.
    """
    pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")
    try:  # pragma: no cover - exercised once the frontend lands
        rust_index: Any = importlib.import_module("wardline.rust.index")
        rust_qualname: Any = importlib.import_module("wardline.rust.qualname")
    except ImportError:
        pytest.skip("wardline.rust frontend not implemented yet (slice-1 WP2)")
    return rust_index, rust_qualname


@pytest.mark.parametrize("case", _CORPUS["entities"], ids=lambda c: c["name"])
def test_entity_qualnames(case: dict[str, Any]) -> None:
    rust_index, _ = _rust_producer()
    # SP2 landed: sp2 rows assert for real alongside slice-1 (no xfail tier remains).
    # Phase 1b contract: the FULL ordered ten-kind emission for `source` rooted at
    # `module_path`, kind-mapped semantic `method` -> id-kind `function` (the one
    # legal projection; everything else must match the corpus byte-for-byte AND
    # row-for-row in order).
    found = [
        (e.qualname, "function" if e.kind == "method" else e.kind)
        for e in rust_index.discover_rust_entities(case["source"], module=case["module_path"])
    ]
    assert found == _expected_all_pairs(case)


@pytest.mark.parametrize("route", _CORPUS["module_route"], ids=lambda r: r["name"])
def test_module_route(route: dict[str, Any]) -> None:
    _, rust_qualname = _rust_producer()
    # module_route rows drive the PURE-FILESYSTEM route directly — a bare
    # (crate, src_root, file) call with NO declaring-file context. `path_attr_known_gap`
    # is the Amendment-8 FALLBACK pin: #[path]-aware routing is the SEPARATE
    # logical_module_path entry point (test_module_mounts below); a route with no mount
    # covering the file MUST be byte-identical to this one.
    got = rust_qualname.rust_module_route(crate=route["crate"], src_root=route["src_root"], file=route["file"])
    assert got == route["expected_module"]


@pytest.mark.parametrize("case", _CORPUS["module_mounts"], ids=lambda c: c["name"])
def test_module_mounts(case: dict[str, Any]) -> None:
    """ADR-049 Amendment 8: the #[path] mount overlay routes end-to-end — mount
    discovery over the case's file map (rustc's relative-path rule, cross-form @cfg
    twins, cfg-twin inline-mod prefix composition), fixed-point resolution (chains,
    R5 first-wins), and the filesystem fallback for macro-invisible mounts."""
    _rust_producer()  # tree-sitter gate (skips when the wardline[rust] extra is absent)
    rust_mounts: Any = importlib.import_module("wardline.rust.mounts")
    # Every module_mounts case lays its files under `src/` at the project root —
    # src_root is the constant "src" by corpus construction.
    overlay = rust_mounts.build_mount_overlay(case["files"], crate=case["crate"], src_root="src")
    for file, expected in case["expect"].items():
        assert overlay.logical_module_path(file) == expected, f"{case['name']}: {file}"
