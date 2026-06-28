"""Wardline-authored loomweave taint-fact wire (the ``wardline-taint-1`` blob)
frozen to a vendored byte golden.

``wardline-taint-fact-wire.golden.json`` is the representative set of taint-fact
write payloads wardline produces for the SP9/T3.4 seam: wardline WRITES per-entity
``wardline-taint-1`` taint-fact blobs into loomweave's taint store, and loomweave
stores the ``wardline_json`` blob VERBATIM (opaque to it) and keys/freshness-gates
on the top-level ``content_hash_at_compute`` column. The wire here is the list of
fact payloads ``build_taint_facts`` emits — one per function entity — each carrying
the opaque blob, the composed dotted ``qualname``, and the top-level
``content_hash_at_compute`` (blake3 of the analyzed file, whole-file raw bytes).

The corpus is generated from ONE fixed, deterministic source module (``TAINT_SOURCE``
below) and covers the wire shapes that matter:

* a trust-decorated root entity (``@external_boundary``) with an empty ``findings``
  list and a ``dead_code_root.is_root: true`` signal;
* an undecorated non-root entity (``dead_code_root.is_root: false``) with a
  ``fallback`` taint source;
* a ``@trusted`` sink entity whose ``actual_return`` is the laundered ``EXTERNAL_RAW``
  with a resolved ``contributing_callee_qualname`` AND a real PY-WL-101 finding (rule_id
  / fingerprint / path / line_start) in its ``findings`` list.

So a silent change to ANY of those wire shapes — the ``schema_version`` stamp, the
``dead_code_root`` projection, the ``taint`` sub-object keys, the per-finding fields,
or the blake3 ``content_hash_at_compute`` derivation — reds.

WARDLINE IS THE AUTHORITY for this seam — it OWNS the taint-fact blob via
``wardline.loomweave.facts.build_taint_facts`` (loomweave stores the blob opaquely).
That makes the two-sided protection a two-layer affair (mirroring the scan-results /
finding-identity / suppression-filter contracts):

* Layer-1 (``test_golden_matches_blob_pin``): a git-blob byte-pin on the vendored
  golden, so any silent edit to the shared taint-fact corpus reds the default PR
  suite. On its OWN this is CIRCULAR — wardline pins wardline's own bytes.
* Producer-source recheck (``test_golden_matches_live_producer``): the non-circular
  break. It scans the SAME fixed source through wardline's LIVE runtime
  ``build_taint_facts`` and asserts the regenerated fact list EQUALS the frozen golden.
  The frozen bytes are tied to the live producer, so if the blob shape, the taint
  projection, the dead-code-root signal, the finding fields, or the blake3 freshness
  derivation drifts from the golden without a re-vendor, it reds even though the
  byte-pin still passes. The assert calls ``build_taint_facts`` INLINE (the imported
  symbol + ``==`` on one physical line) so the equality is tied to the live runtime,
  not to the golden restating itself.

SCOPE — what this golden pins and what it deliberately does NOT:

* PINNED: the per-fact projection — the list ``build_taint_facts`` emits, each item's
  ``{qualname, content_hash_at_compute, wardline_json}`` (and the opaque blob loomweave
  stores verbatim). This is the load-bearing payload the consumer keys and freshness-gates on.
* NOT pinned (and why): the outer HTTP write envelope ``{"project": <id>, "facts": [...]}``
  POSTed to ``POST /api/wardline/taint-facts`` (in 2000-item chunks) is applied in
  ``wardline.loomweave.client.LoomweaveClient.write_taint_facts``, AFTER this projection. Its
  ``project`` value is runtime/config-derived (not a deterministic byte to freeze), so the
  envelope is out of scope for a byte-golden; the ``facts`` array it wraps IS this golden.
* NOT pinned (and why): the HMAC request signature wardline computes to WRITE these facts is
  non-deterministic at runtime (the signed message embeds a fresh timestamp + nonce). Its
  deterministic core (the five-field canonical message + the lowercase-hex HMAC-SHA256 over
  fixed inputs) is pinned byte-exactly in ``tests/unit/loomweave/test_hmac.py`` against
  loomweave's verifier (``auth.rs`` ``canonical_hmac_message``).

RE-VENDOR PROCEDURE: if you deliberately change the taint-fact wire (e.g. add a blob
field or a taint sub-key), regenerate the golden from ``build_taint_facts`` with the
SAME ``TAINT_SOURCE`` below, recompute the blob SHA and update ``UPSTREAM_BLOB_SHA``
in the SAME commit — the producer-source recheck will otherwise red.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from wardline.core.run import run_scan
from wardline.loomweave.facts import build_taint_facts

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "wardline-taint-fact-wire.golden.json"

# The fixed, deterministic source the golden is generated from. Held here so the
# producer-source recheck scans the EXACT same bytes — the blake3
# ``content_hash_at_compute`` is whole-file raw bytes, so this string must be
# byte-for-byte the source the golden was vendored from.
TAINT_SOURCE = (
    "from wardline.decorators import external_boundary, trusted\n"
    "\n"
    "\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
    "\n"
    "\n"
    "def helper(p):\n"
    "    return p\n"
    "\n"
    "\n"
    "@trusted\n"
    "def leaky(p):\n"
    "    return read_raw(p)\n"
)

# Layer-1 byte-pin: the git-blob SHA-1 of wardline-taint-fact-wire.golden.json.
# Recomputed below as hashlib.sha1(b"blob %d\0" % len(data) + data). Any edit to the
# vendored golden without a matching re-pin reds the default PR suite.
UPSTREAM_BLOB_SHA = "297ea60e99db857097dd0f38938ded713fed7a9b"


def _scan_fixed_source(tmp_path: Path) -> tuple[Path, object]:
    """Scan the fixed TAINT_SOURCE under a temp project root. Returns (root, ScanResult)
    so the recheck can call build_taint_facts(result, root) INLINE on the assert line."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(TAINT_SOURCE, encoding="utf-8")
    return proj, run_scan(proj)


def test_golden_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored taint-fact golden byte-pins to its
    git blob hash. ANY edit without a matching re-pin reds the default PR suite. On its
    own this pin is wardline-pins-wardline (circular); the non-circular protection is
    ``test_golden_matches_live_producer`` below, which regenerates the fact list from the
    LIVE producer."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = GOLDEN_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored taint-fact wire golden changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, regenerate the golden from build_taint_facts with the "
        "TAINT_SOURCE in this module, update UPSTREAM_BLOB_SHA in the same commit, and re-run "
        "conformance (see the RE-VENDOR PROCEDURE at the top of this module); if not, revert the edit."
    )


def test_golden_matches_live_producer(tmp_path: Path) -> None:
    """PRODUCER-SOURCE recheck (non-circular): scan the SAME fixed source through wardline's
    LIVE runtime ``build_taint_facts`` and assert the regenerated fact list EQUALS the frozen
    golden. This ties the byte-pinned golden to the real producer, so a blob-shape drift (a
    taint sub-key renamed/added/dropped, the dead-code-root signal changed, a finding field
    altered, the blake3 freshness derivation changed) without a re-vendor reds even though the
    byte-pin still passes.

    The producer is called INLINE on the assert line (the imported ``build_taint_facts`` symbol
    + ``==`` on one physical line) so the equality is tied to the live runtime, not to the golden
    restating itself — this is the producer-source recheck the seam-registry gate detects."""
    golden = json.loads(GOLDEN_PATH.read_text("utf-8"))
    assert golden, "taint-fact golden carries no facts — a vacuous corpus must not pass"
    proj, result = _scan_fixed_source(tmp_path)
    assert build_taint_facts(result, proj) == golden


def test_golden_covers_the_load_bearing_wire_shapes() -> None:
    """Guard the corpus against silently shrinking to a vacuous/uninteresting set: assert the
    frozen golden still exercises the wire shapes the seam's value rests on (root + non-root
    dead-code signal, anchored + fallback taint, a resolved contributing callee, and a real
    finding with the SP9 blob fields). Pure on-the-golden assertions — no producer call — so a
    re-vendor that drops one of these shapes is caught here even before the recheck runs."""
    golden = json.loads(GOLDEN_PATH.read_text("utf-8"))
    by_qualname = {f["qualname"]: f for f in golden}
    assert {"svc.read_raw", "svc.helper", "svc.leaky"} <= set(by_qualname)

    # Every fact carries the SP9 envelope: the opaque blob, the dotted qualname, and the
    # top-level freshness column repeated inside the blob.
    for qualname, fact in by_qualname.items():
        blob = fact["wardline_json"]
        assert blob["schema_version"] == "wardline-taint-1"
        assert blob["qualname"] == qualname
        assert fact["content_hash_at_compute"] == blob["content_hash_at_compute"]
        assert len(fact["content_hash_at_compute"]) == 64  # blake3 hex

    # A trust-decorated root entity (dead-code-root signal on) vs an undecorated non-root.
    assert by_qualname["svc.read_raw"]["wardline_json"]["dead_code_root"]["is_root"] is True
    assert by_qualname["svc.helper"]["wardline_json"]["dead_code_root"]["is_root"] is False

    # The @trusted sink: laundered EXTERNAL_RAW with a resolved contributing callee AND a
    # real PY-WL-101 finding carrying the per-finding wire fields.
    leaky_blob = by_qualname["svc.leaky"]["wardline_json"]
    assert leaky_blob["taint"]["actual_return"] == "EXTERNAL_RAW"
    assert leaky_blob["taint"]["contributing_callee_qualname"] == "svc.read_raw"
    finding = next(f for f in leaky_blob["findings"] if f["rule_id"] == "PY-WL-101")
    assert set(finding) == {"rule_id", "fingerprint", "path", "line_start"}
    assert len(finding["fingerprint"]) == 64
