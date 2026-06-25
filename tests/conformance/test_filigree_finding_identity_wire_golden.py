"""Wardline-authored finding IDENTITY (fingerprint/qualname/spans) frozen to a
vendored byte golden.

``wardline-finding-identity-wire.golden.json`` is the representative set of
finding-identity vectors wardline produces: for fixed deterministic inputs
(rule_id / path / qualname / taint_path / location), the
``{fingerprint, qualname, spans}`` the producer emits. It is the cross-tool JOIN
KEY contract — Filigree keys issues on ``(scan_source, fingerprint)`` and the
baseline / waiver stores key on the fingerprint, so a silent change to how that
identity is DERIVED (the hash formula, the scheme stamp, the qualname
normalization, the span projection) would silently re-key every downstream
verdict. This corpus reds on any such change.

WHY THIS SEAM IS DISTINCT from the scan-results wire golden
(``test_filigree_scan_results_wire_golden.py``): that golden uses CANNED
fingerprints (``"a"*64`` …) and drops columns, so it never exercises the
fingerprint *derivation* at all. THIS corpus pins the derivation itself —
``compute_finding_fingerprint`` run on fixed inputs, the ``wlfp2`` scheme stamp
via ``format_fingerprint``, the ``_to_wire_qualname`` property-accessor
normalization, and the full ``Location``/``to_jsonl`` span projection incl.
columns. The ``collision_pair_*`` vectors pin the soundness property the join
key rests on: two findings sharing ``(rule_id, path, qualname)`` that differ ONLY
in the source-derived ``taint_path`` discriminator MUST produce DISTINCT
fingerprints (else one is silently dropped on the Filigree join).

WARDLINE IS THE AUTHORITY for this seam — it OWNS finding identity via
``wardline.core.finding.{compute_finding_fingerprint, format_fingerprint,
FINGERPRINT_SCHEME, _to_wire_qualname}`` and ``Finding.to_jsonl``. That makes the
two-sided protection a two-layer affair (mirroring the scan-results /
suppression-filter contracts):

* Layer-1 (``test_golden_matches_blob_pin``): a git-blob byte-pin on the vendored
  golden, so any silent edit to the shared identity corpus reds the default PR
  suite. On its OWN this is CIRCULAR — wardline pins wardline's own bytes.
* Producer-source recheck (``test_golden_matches_live_identity_producer``): the
  non-circular break. It imports wardline's LIVE runtime identity producers and
  asserts, for each vector, that re-deriving the identity from the SAME fixed
  inputs reproduces the frozen golden values. The frozen bytes are tied to the
  live producers, so if the hash formula / scheme / qualname-normalization / span
  projection drifts from the golden without a re-vendor, it reds even though the
  byte-pin still passes.

RE-VENDOR PROCEDURE: if you deliberately change finding identity (e.g. bump the
fingerprint scheme wlfp2 -> wlfp3, or add a span field), regenerate the golden
from the producers with the SAME inputs below, recompute the blob SHA and update
``UPSTREAM_BLOB_SHA`` in the SAME commit — the producer-source recheck will
otherwise red.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

# Module-qualified import (``from wardline.core import finding``) — NOT individual
# names. This keeps the import on ONE short physical line so the seam-registry gate's
# ``_imported_wardline_symbols`` regex (``^...$`` anchored per physical line) captures
# the ``finding`` module symbol; the producer-source recheck then names ``finding`` on
# each ``assert finding.<producer>(...) == ...`` line, satisfying the gate's
# ``_has_producer_source_recheck`` while staying ruff-isort clean (a names-list import
# of all 8 symbols exceeds the 120-col limit and isort would split it across lines,
# hiding the symbols from the gate's per-line regex).
from wardline.core import finding

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "wardline-finding-identity-wire.golden.json"

# Layer-1 byte-pin: the git-blob SHA-1 of wardline-finding-identity-wire.golden.json.
# Recomputed below as hashlib.sha1(b"blob %d\0" % len(data) + data). Any edit to the
# vendored golden without a matching re-pin reds the default PR suite.
UPSTREAM_BLOB_SHA = "4eec05f0c53b301cb433331092731c567a7754db"


def _golden() -> dict:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def test_golden_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored identity golden byte-pins to its
    git blob hash. ANY edit without a matching re-pin reds the default PR suite. On its
    own this pin is wardline-pins-wardline (circular); the non-circular protection is
    ``test_golden_matches_live_identity_producer`` below, which regenerates each vector's
    identity from the LIVE producers."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = GOLDEN_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored finding-identity wire golden changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, regenerate the golden from the identity producers with the "
        "SAME inputs recorded in each vector, update UPSTREAM_BLOB_SHA in the same commit, and re-run "
        "conformance (see the RE-VENDOR PROCEDURE at the top of this module); if not, revert the edit."
    )


def test_golden_scheme_matches_live_scheme() -> None:
    """The corpus records the scheme it was captured under; tie it to the LIVE
    ``FINGERPRINT_SCHEME`` so a scheme bump (wlfp2 -> wlfp3) is a visible, accountable
    corpus delta rather than a silent re-key."""
    golden = _golden()
    assert golden["fingerprint_scheme"] == finding.FINGERPRINT_SCHEME


def test_fingerprint_derivation_ties_to_live_producer() -> None:
    """Anchor the producer-source recheck to the HEADLINE producer
    (``compute_finding_fingerprint``) — the hash derivation that distinguishes this seam
    from the canned-fingerprint scan-results golden. The live producer is called INLINE
    on the assert line (named ``finding`` symbol + ``==`` on one physical line) so the
    seam-registry gate's ``_has_producer_source_recheck`` is satisfied by the fingerprint
    derivation itself, not only by the ancillary scheme/qualname rechecks. Kept on one
    line (short locals; the keyword-only args otherwise blow the 120-col limit and ruff
    would wrap it, hiding the symbol from the gate's per-line regex)."""
    i = _golden()["vectors"]["singleton_no_taint_path"]["inputs"]
    rid, pth, qn, tp = i["rule_id"], i["path"], i["qualname"], i["taint_path"]
    expected = _golden()["vectors"]["singleton_no_taint_path"]["bare_fingerprint"]
    assert finding.compute_finding_fingerprint(rule_id=rid, path=pth, qualname=qn, taint_path=tp) == expected


def test_golden_matches_live_identity_producer() -> None:
    """PRODUCER-SOURCE recheck (non-circular): for each frozen vector, re-derive the
    finding identity from wardline's LIVE runtime producers with the SAME fixed inputs
    and assert each producer's output EQUALS the frozen golden value. This ties the
    byte-pinned golden to the real producers, so a derivation drift (the hash formula,
    the ``wlfp2`` scheme stamp, the ``_to_wire_qualname`` normalization, or the
    ``Location``/``to_jsonl`` span projection) without a re-vendor reds even though the
    byte-pin still passes.

    Each ``assert`` calls a producer INLINE and names the imported wardline symbol on the
    assertion line (not a pre-computed local), so the equality is tied to the live runtime
    rather than to the golden restating itself."""
    golden = _golden()
    vectors = golden["vectors"]
    assert vectors, "identity golden carries no vectors — a vacuous corpus must not pass"

    for name, vec in vectors.items():
        inp = vec["inputs"]
        loc = inp["location"]

        # (1) fingerprint DERIVATION: the bare 64-hex digest from the live hash formula.
        # The live producer is called INLINE (not a pre-computed local) so the equality is
        # tied to the runtime, not to the golden restating itself.
        live_bare = finding.compute_finding_fingerprint(
            rule_id=inp["rule_id"], path=inp["path"], qualname=inp["qualname"], taint_path=inp["taint_path"]
        )
        assert live_bare == vec["bare_fingerprint"], f"{name}: bare fingerprint drift"

        # (2) the wlfp2 SCHEME STAMP applied to that digest for the wire/store.
        live_stamped = finding.format_fingerprint(finding.FINGERPRINT_SCHEME, vec["bare_fingerprint"])
        assert live_stamped == vec["stamped_fingerprint"], f"{name}: stamped fingerprint drift"

        # (3) the cross-tool reconciliation QUALNAME (property-accessor normalization).
        # Call the live producer INLINE on the assert line (``finding._to_wire_qualname``)
        # so the equality is tied to the runtime symbol — this is the producer-source
        # recheck the seam-registry gate detects (``finding`` + ``==`` on one physical line).
        qn = inp["qualname"]
        if qn is None:
            assert vec["wire_qualname"] is None, f"{name}: wire qualname drift (expected null)"
        else:
            assert finding._to_wire_qualname(qn) == vec["wire_qualname"], f"{name}: wire qualname drift"

        # (4) the wire SPAN / identity projection emitted by Finding.to_jsonl. Build the
        # finding from the recorded inputs and assert its jsonl identity record reproduces
        # the frozen fingerprint, qualname, and full span (incl. columns).
        live = finding.Finding(
            rule_id=inp["rule_id"],
            message="identity vector",
            severity=finding.Severity.ERROR,
            kind=finding.Kind.DEFECT,
            location=finding.Location(
                path=loc["path"],
                line_start=loc["line_start"],
                line_end=loc["line_end"],
                col_start=loc["col_start"],
                col_end=loc["col_end"],
            ),
            fingerprint=vec["bare_fingerprint"],
            qualname=inp["qualname"],
        )
        rec = json.loads(live.to_jsonl())
        assert rec["fingerprint"] == vec["wire_fingerprint"], f"{name}: to_jsonl fingerprint drift"
        assert rec["qualname"] == vec["wire_jsonl_qualname"], f"{name}: to_jsonl qualname drift"
        assert rec["location"] == vec["spans"], f"{name}: to_jsonl span projection drift"


def test_collision_pair_fingerprints_are_distinct() -> None:
    """The soundness property the join key rests on: two findings sharing
    ``(rule_id, path, qualname)`` that differ ONLY in the source-derived ``taint_path``
    discriminator MUST produce DISTINCT fingerprints. If they collided, one would be
    silently dropped on the Filigree ``(scan_source, fingerprint)`` join. Re-derive both
    from the live producer and assert non-collision (so a hash-formula change that
    dropped ``taint_path`` from the digest reds here, not just on the byte-pin)."""
    golden = _golden()
    a = golden["vectors"]["collision_pair_a"]["inputs"]
    b = golden["vectors"]["collision_pair_b"]["inputs"]

    assert (a["rule_id"], a["path"], a["qualname"]) == (b["rule_id"], b["path"], b["qualname"]), (
        "collision-pair vectors must share (rule_id, path, qualname) so the test is non-vacuous"
    )
    assert a["taint_path"] != b["taint_path"], "collision-pair vectors must differ in taint_path"

    fp_a = finding.compute_finding_fingerprint(
        rule_id=a["rule_id"], path=a["path"], qualname=a["qualname"], taint_path=a["taint_path"]
    )
    fp_b = finding.compute_finding_fingerprint(
        rule_id=b["rule_id"], path=b["path"], qualname=b["qualname"], taint_path=b["taint_path"]
    )
    assert fp_a != fp_b, "distinct findings collapsed to one fingerprint — the join key is unsound"
