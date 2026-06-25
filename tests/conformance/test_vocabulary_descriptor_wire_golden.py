"""Wardline-authored NG-25 trust-vocabulary descriptor frozen to a vendored byte golden.

``wardline-vocabulary-descriptor.golden.yaml`` is the descriptor wardline emits
to ``.weft/wardline/vocabulary.yaml`` (and ships in the wheel as
``wardline/core/vocabulary.yaml``). Loomweave's Python plugin is the real
consumer: ``loomweave_plugin_python.wardline_descriptor.load_wardline_descriptor``
reads this file's BYTES (it never imports wardline). It GATES ON ``version``
(asserting the descriptor version equals its ``EXPECTED_DESCRIPTOR_VERSION`` —
currently ``wardline-generic-2``, matching wardline's ``REGISTRY_VERSION``, so a
one-sided bump trips loomweave's ``version_skew`` path), PARSES ``entries``
(``canonical_name`` / ``group`` / ``attrs``) into a ``WardlineVocabulary``, and
TOLERATES the ``schema`` field without acting on it (its schema-format-version
handling is deferred to loomweave's own Task B). It then threads the vocabulary
into the extractor to emit ``wardline:external_boundary`` /
``wardline:trusted`` ``entity_tags`` (which seed loomweave's dead-code
reachability roots in ``crates/loomweave-mcp/src/catalogue/shortcuts.rs``). So
this seam is a genuine two-sided producer↔consumer wire, not a one-sided internal
export.

WARDLINE IS THE AUTHORITY for this seam — it OWNS the trust-vocabulary via
``wardline.core.registry.REGISTRY`` and serializes it through
``wardline.core.descriptor.build_vocabulary_descriptor`` /
``descriptor_to_yaml``. That makes the protection a two-layer affair (mirroring
the suppression-filter and scan-results-wire contracts):

* Layer-1 (``test_golden_matches_blob_pin``): a git-blob byte-pin on the vendored
  golden, so any silent edit to the descriptor wire reds the default PR suite. On
  its OWN this is CIRCULAR — wardline pins wardline's own bytes.
* Producer-source recheck (``test_golden_matches_live_descriptor_producer``): the
  non-circular break. It imports wardline's LIVE runtime ``descriptor_to_yaml`` /
  ``build_vocabulary_descriptor`` and asserts the bytes / dict they regenerate
  EQUAL the frozen golden. The frozen bytes are tied to the live producer, so if
  REGISTRY (or the serializer) drifts from the golden — a decorator added/removed,
  a group/attr changed, the schema or version bumped — it reds even though the
  byte-pin still passes.

The consumer-side oracle lives in the loomweave repo (its python plugin parses
these bytes); it is cited as prose evidence — this conformance row pins the
producer-authored descriptor bytes, which is what makes the two sides agree.

RE-VENDOR PROCEDURE: if you deliberately change the vocabulary (e.g. add a
decorator) or the descriptor format, regenerate the golden from the producer
(``.venv/bin/wardline vocab > tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml``,
equivalently ``descriptor_to_yaml()``), recompute the blob SHA and update
``UPSTREAM_BLOB_SHA`` in the SAME commit — the producer-source recheck will
otherwise red. Keep ``src/wardline/core/vocabulary.yaml`` in lockstep (its own
byte-identity test in tests/unit/core/test_descriptor.py guards that).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from wardline.core.descriptor import build_vocabulary_descriptor, descriptor_to_yaml

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.golden.yaml"

# Layer-1 byte-pin: the git-blob SHA-1 of wardline-vocabulary-descriptor.golden.yaml.
# Recomputed below as hashlib.sha1(b"blob %d\0" % len(data) + data). Any edit to the
# vendored golden without a matching re-pin reds the default PR suite.
UPSTREAM_BLOB_SHA = "f5ad8d2346ffb6ea75aa469e423c6c7cfd16d40a"


def test_golden_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored descriptor golden byte-pins to
    its git blob hash. ANY edit without a matching re-pin reds the default PR suite.
    On its OWN this pin is wardline-pins-wardline (circular); the non-circular
    protection is ``test_golden_matches_live_descriptor_producer`` below, which
    regenerates the bytes from the LIVE producer."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = GOLDEN_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored vocabulary-descriptor golden changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, regenerate the golden from descriptor_to_yaml() "
        "(`.venv/bin/wardline vocab > tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml`), "
        "update UPSTREAM_BLOB_SHA in the same commit, keep src/wardline/core/vocabulary.yaml in lockstep, "
        "and re-run conformance (see the RE-VENDOR PROCEDURE at the top of this module); if not, revert the edit."
    )


def test_golden_matches_live_descriptor_producer() -> None:
    """PRODUCER-SOURCE recheck (non-circular): regenerate the descriptor from
    wardline's LIVE runtime ``descriptor_to_yaml`` and assert the bytes EQUAL the
    frozen golden. This ties the byte-pinned golden to the real producer (and
    through it to REGISTRY), so a vocabulary/format drift — a decorator
    added/removed, a group/attr changed, the schema or version bumped — without a
    re-vendor reds even though the byte-pin still passes.

    The loomweave python-plugin consumer reads these exact bytes
    (``.weft/wardline/vocabulary.yaml``) via ``yaml.safe_load`` and gates on
    ``version`` / ``entries``, so freezing the producer bytes is what holds the two
    sides in agreement."""
    golden_text = GOLDEN_PATH.read_text("utf-8")
    assert descriptor_to_yaml() == golden_text


def test_golden_dict_matches_live_descriptor_producer() -> None:
    """Companion structured recheck: the live ``build_vocabulary_descriptor`` dict
    must equal the parsed golden. Catches a same-bytes-different-semantics drift the
    YAML compare alone could miss (it asserts on the structured envelope the
    consumer actually parses: schema / version / entries)."""
    import yaml

    golden = yaml.safe_load(GOLDEN_PATH.read_text("utf-8"))
    assert build_vocabulary_descriptor() == golden
