# tests/conformance/test_loomweave_rust_qualname_parity.py
"""Pin Wardline's *Rust* qualname producer against Loomweave's normative corpus.

For Rust, **Loomweave is authoritative** (its whole-tree ``syn`` extractor is the
oracle; the dialect is fixed by Loomweave ADR-049). This INVERTS the Python
arrangement: Wardline *vendors* ``qualnames_rust.json`` and reproduces its
``expected`` qualnames byte-for-byte from the tree-sitter frontend — Wardline is
the *second producer*, it MINTS the same locator string and never parses it.

Provenance — re-vendor when Loomweave bumps the corpus:
    source: loomweave  feat/rust-plugin-spec  @ 1bd5855  (fixtures/qualnames_rust.json,
            blob 6c0aee1, extractor-generated, locked by
            crates/loomweave-plugin-rust/tests/qualname_conformance.rs)
    vendored byte-identical to tests/conformance/qualnames_rust.json (2026-06-09).
    NOTE: this is the **ADR-049 amendment (Option b)** corpus — the inherent-impl
    source-order ordinal was DROPPED (`Foo.impl#<>.bar`, not `impl#<>#0.bar`) and
    same-signature inherent impls merge. The 1bd5855 re-vendor additionally adds the
    two cfg-twin-on-impl trip-wire cases (``inherent_impl_cfg_twin`` /
    ``trait_impl_cfg_twin``) — without them the gate never exercised the ``@cfg``
    suffix landing ON an impl key, so an extractor that omitted it would have passed
    while silently merging cfg-twin impls. ⚠️ The earlier federation handshake doc
    (loomweave docs/federation/2026-06-09-rust-qualname-dialect-response.md) still
    describes the *old* ordinal form — it is intentionally left intact as history and
    is SUPERSEDED by the Phase 1b change-set
    (docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md), which
    is the authoritative description of this corpus. Where any doc and the live
    extractor + this corpus diverge, the extractor + corpus are the oracle.

Status: the Rust frontend (``wardline.rust.*``) now EXISTS (slice-1 WP2 landed), so
the *producer-parity* tests below run live (``_rust_producer`` resolves
``wardline.rust.index`` — they no longer skip). The *structural* self-tests also run
and catch a malformed / stale re-vendor. SP2 rows still ``xfail`` (whole-tree view).

The comparison rule (from the corpus ``_consumer_comparison`` key — do NOT use raw
list-equality against ``expected``):
  1. The byte-exact obligation is the ``qualname`` of every NON-``module`` row.
  2. ``kind`` is the locator id-kind (``function`` for every callable); Wardline's
     semantic ``method`` ↔ id-kind ``function`` for impl fns. Compare qualname-only.
  3. ``module`` rows are validated via the ``module_route`` section, not re-emitted.
Wardline emits only callables (functions), so the non-vacuous form of (1) is
*set-equality on the function-kind qualnames* (catches both missing and extra).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

_CORPUS: dict[str, Any] = json.loads((Path(__file__).parent / "qualnames_rust.json").read_text("utf-8"))

_KNOWN_TIERS = {"slice-1", "sp2"}
# The ADR-049-amendment corpus adds `impl` entities (one per merged impl block) and
# `macro` rows. Wardline emits only `function` callables, so the comparison rule
# (set-equality on function-kind qualnames) is unchanged; the extra kinds must be
# *known* so test_expected_kinds_are_known stays a real guard, not a false failure.
_KNOWN_KINDS = {"function", "struct", "module", "impl", "macro"}


def _expected_function_qualnames(case: dict[str, Any]) -> set[str]:
    """The contract's obligation surface for a function-only producer: the set of
    ``function``-kind qualnames in the case (``module``/``struct`` rows excluded)."""
    return {row["qualname"] for row in case["expected"] if row["kind"] == "function"}


# --------------------------------------------------------------------------- #
# Structural self-tests — run NOW (no frontend / tree-sitter needed). These pin
# the vendored corpus so a malformed or stale re-vendor fails loudly in CI.
# --------------------------------------------------------------------------- #


def test_corpus_shape() -> None:
    for key in ("_doc", "_dialect_summary", "_consumer_comparison", "module_route", "entities"):
        assert key in _CORPUS, f"vendored corpus is missing the '{key}' section"
    assert _CORPUS["entities"], "corpus has no entity cases"
    assert _CORPUS["module_route"], "corpus has no module_route cases"
    assert _CORPUS["_consumer_comparison"].strip(), "the comparison contract must travel with the data"


def test_reproducibility_tiers_are_known() -> None:
    # Guard: a resync that introduces a new tier would silently bypass the
    # slice-1-runs / sp2-xfails gating below.
    tiers = {c["reproducibility"] for c in _CORPUS["entities"]}
    tiers |= {r["reproducibility"] for r in _CORPUS["module_route"]}
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
# Producer-parity tests — SKIP until the Rust frontend exists (slice-1 WP2).
# --------------------------------------------------------------------------- #


def _rust_producer() -> tuple[Any, Any]:
    """Resolve the Rust frontend producer, or skip. WP2 wires the real API here;
    the corpus then becomes a live byte-for-byte parity gate.

    Expected slice-1 surface (pinned in the plan's WP2):
      - ``wardline.rust.index.discover_rust_entities(source: str, *, module: str)
        -> Sequence[RustEntity]`` (parses internally; entities carry ``.qualname``;
        deriving ``module``/crate from Cargo.toml is SP2, so the case supplies it);
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
    if case["reproducibility"] == "sp2":  # pragma: no cover - flips to hard assert at SP2
        pytest.xfail("sp2 row: needs the whole-tree view (crate name / cross-file route)")
    # WP2 contract: emit callable entities for `source` rooted at `module_path`.
    found = {e.qualname for e in rust_index.discover_rust_entities(case["source"], module=case["module_path"])}
    assert found == _expected_function_qualnames(case)


@pytest.mark.parametrize("route", _CORPUS["module_route"], ids=lambda r: r["name"])
def test_module_route(route: dict[str, Any]) -> None:
    _, rust_qualname = _rust_producer()
    if route["reproducibility"] == "sp2":  # pragma: no cover - flips to hard assert at SP2
        pytest.xfail("sp2 row (e.g. #[path] known gap): correct routing is a shared SP2 task")
    # WP2 contract: route a file to its dotted module given the crate + src_root.
    got = rust_qualname.rust_module_route(crate=route["crate"], src_root=route["src_root"], file=route["file"])
    assert got == route["expected_module"]
