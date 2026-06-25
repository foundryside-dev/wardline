# tests/conformance/test_loomweave_qualname_parity.py
"""Pin Wardline's qualname producer against Loomweave's normative parity fixture.

The reconciliation CONSUMER is unbuilt in loomweave 1.0.0; this converts the
producer byte-equality from assumption to a committed CI test. Wardline returns
``None`` where Loomweave returns ``""`` for a top-level ``__init__.py`` — the
``None <-> ""`` mapping below is the documented, semantically-equivalent boundary.

Drift alarm (two layers — the Python axis of the qualname conformance seam):
    1. Byte-pin (default suite, ``test_vendored_fixture_matches_blob_pin``):
       ``VENDORED_BLOB_SHA`` below pins the *vendored* fixture's git blob hash. ANY
       byte change to the vendored copy fails loudly. NOTE the asymmetry with the
       Rust corpus: the vendored Python fixture is NOT byte-identical to upstream —
       it adds a repo-local ``_wardline_provenance`` wrapper key and carries a
       SHORTER ``$comment`` than upstream (the upstream ``$comment`` accrues an
       integration-TODO note that is documentation, not normalization content). So
       this pin is the *vendored* blob (``82cf10e5…``), which deliberately differs
       from the upstream blob; Layer 2 rechecks the SUBSTANTIVE content vs upstream.
    2. Live recheck (opt-in, ``-m loomweave_drift``,
       ``test_vendored_fixture_matches_live_sibling_substantive``): compares the
       SUBSTANTIVE normalization content (``rules_source`` + both vector arrays)
       against the sibling loomweave checkout's upstream fixture, IGNORING the
       non-substantive ``_wardline_provenance`` / ``$comment`` metadata that
       legitimately diverges; skips when the checkout is absent (CI).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from wardline.core.qualname import module_dotted_name

_FIXTURE_PATH = Path(__file__).parent / "loomweave_qualname_parity.json"
_FIXTURE = json.loads(_FIXTURE_PATH.read_text("utf-8"))

# The git blob hash of the VENDORED fixture (tests/conformance/loomweave_qualname_parity.json).
# Unlike the Rust corpus, this is NOT byte-identical to upstream: the vendored copy adds a
# ``_wardline_provenance`` wrapper key and a repo-local (shorter) ``$comment``, so this SHA
# (the vendored blob) deliberately differs from the upstream blob. Re-vendors update this
# constant in the SAME commit as the new bytes; Layer 2 below rechecks the substantive
# content against upstream and ignores the diverging metadata.
VENDORED_BLOB_SHA = "82cf10e586fc38d252734b48f30adbe58f38c440"

# Top-level fixture keys that carry the SUBSTANTIVE normalization contract (the part both
# the vendored copy and upstream MUST agree on). The complement — ``_wardline_provenance``
# (vendored-only wrapper) and ``$comment`` (documentation that legitimately diverges from
# upstream) — is excluded from the Layer-2 recheck by construction below.
_SUBSTANTIVE_KEYS = frozenset({"rules_source", "module_normalization_vectors", "qualified_name_vectors"})
_NON_SUBSTANTIVE_KEYS = frozenset({"_wardline_provenance", "$comment"})


@pytest.mark.parametrize("vec", _FIXTURE["module_normalization_vectors"], ids=lambda v: v["file_path"])
def test_module_normalization(vec: dict[str, Any]) -> None:
    got = module_dotted_name(vec["file_path"])
    expected = vec["expected_module"]
    if expected == "":
        assert got is None  # Wardline's "emit no entity" sentinel == Loomweave's empty+rejected
    else:
        assert got == expected


@pytest.mark.parametrize(
    "vec",
    [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "function"],
    ids=lambda v: v["expected_qualified_name"],
)
def test_function_qualified_name_composition(vec: dict[str, Any]) -> None:
    module = module_dotted_name(vec["file_path"])
    assert module is not None
    assert f"{module}.{vec['qualname']}" == vec["expected_qualified_name"]


def test_qualified_name_vector_kinds_are_known() -> None:
    # Guard against a resync introducing a new `kind` that the parametrized tests above
    # would silently skip, leaving a contract vector unexercised.
    kinds = {v["kind"] for v in _FIXTURE["qualified_name_vectors"]}
    assert kinds <= {"function", "module"}, f"unhandled qualname vector kinds: {kinds - {'function', 'module'}}"


def test_module_kind_vector_prefix_matches() -> None:
    # The single kind=="module" vector: Wardline emits no module ENTITY, but the
    # module dotted prefix it produces must equal the expected qualified_name.
    module_vecs = [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "module"]
    assert module_vecs  # guard: the fixture must contain at least one module vector
    for vec in module_vecs:
        assert module_dotted_name(vec["file_path"]) == vec["expected_qualified_name"]


# --------------------------------------------------------------------------- #
# Corpus drift alarm — the PYTHON axis of the qualname conformance seam. Layer 1
# runs in the default suite (fail-closed byte-pin); Layer 2 is the opt-in live
# recheck against the sibling loomweave checkout.
# --------------------------------------------------------------------------- #


def test_vendored_fixture_matches_blob_pin() -> None:
    """Layer 1 (default suite): the VENDORED fixture byte-pins to its git blob hash.

    This always runs (no marker) and fails closed: any one-byte change to the
    vendored copy reds this test. The pin is the *vendored* blob — which deliberately
    differs from upstream by the ``_wardline_provenance`` wrapper + repo-local
    ``$comment`` (see the module header); upstream parity is Layer 2's job."""
    assert len(VENDORED_BLOB_SHA) == 40 and set(VENDORED_BLOB_SHA) <= set("0123456789abcdef"), (
        f"VENDORED_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {VENDORED_BLOB_SHA!r}"
    )
    data = _FIXTURE_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == VENDORED_BLOB_SHA, (
        f"the vendored fixture changed (git blob {actual}, pinned {VENDORED_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update VENDORED_BLOB_SHA in the same commit and "
        "re-run conformance; if not, someone edited the vendored copy (the upstream fixture is "
        "the only author of the substantive content — re-vendor it verbatim and re-add the "
        "_wardline_provenance wrapper, never hand-edit the vectors)"
    )


def _substantive_view(doc: dict[str, Any]) -> dict[str, Any]:
    """Project a fixture document down to its SUBSTANTIVE normalization content —
    the keys both the vendored copy and upstream must agree on byte-for-byte. The
    blacklist form (drop the non-substantive metadata, keep EVERYTHING else) is
    deliberate: it fails CLOSED if upstream grows a NEW substantive section, where a
    whitelist of ``_SUBSTANTIVE_KEYS`` would silently ignore it. We also assert the
    expected substantive keys are present so a renamed/dropped section reds rather
    than comparing two empty views."""
    view = {k: v for k, v in doc.items() if k not in _NON_SUBSTANTIVE_KEYS}
    missing = _SUBSTANTIVE_KEYS - view.keys()
    assert not missing, f"fixture is missing substantive section(s): {sorted(missing)}"
    return view


@pytest.mark.loomweave_drift
def test_vendored_fixture_matches_live_sibling_substantive() -> None:
    """Layer 2 (opt-in, ``-m loomweave_drift``): the sibling loomweave checkout's
    upstream fixture must match the vendored copy on SUBSTANTIVE content — the
    release-gate drift alarm for the Python axis. Absent checkout (CI) skips;
    substantive divergence FAILS.

    A raw byte-compare would always fail here: the vendored copy adds a
    ``_wardline_provenance`` wrapper and carries a repo-local (shorter) ``$comment``
    than upstream — both are documentation metadata, NOT normalization content.
    ``$comment`` is excluded deliberately (upstream accrues an integration-TODO note
    that the vendored copy intentionally does not mirror). The compared view keeps
    every OTHER key, so a new upstream substantive section would still red."""
    repo = Path(os.environ.get("WARDLINE_LOOMWEAVE_REPO", "/home/john/loomweave"))
    upstream = repo / "docs" / "federation" / "fixtures" / "wardline-qualname-normalization.json"
    if not upstream.is_file():
        pytest.skip(f"no loomweave sibling checkout at {repo} (override via WARDLINE_LOOMWEAVE_REPO)")
    upstream_doc = json.loads(upstream.read_text("utf-8"))
    vendored_doc = json.loads(_FIXTURE_PATH.read_text("utf-8"))
    if _substantive_view(vendored_doc) != _substantive_view(upstream_doc):
        pytest.fail(
            f"upstream {upstream} has drifted from the vendored "
            "tests/conformance/loomweave_qualname_parity.json on SUBSTANTIVE content "
            "(rules_source / module_normalization_vectors / qualified_name_vectors, or a new "
            "upstream section) — re-vendor the substantive content verbatim, bump "
            "VENDORED_BLOB_SHA in the same commit, and conform core/qualname.py until green "
            "(never edit the vectors to match a broken producer)"
        )
