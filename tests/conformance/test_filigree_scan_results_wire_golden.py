"""Wardline-authored scan-results wire frozen to a vendored byte golden.

``wardline-scan-results-wire.golden.json`` is the representative
``POST /api/weft/scan-results`` body wardline produces, frozen so the consumer
(Filigree) can vendor the SAME bytes and drive its real intake against them. It
covers every finding ``Kind`` (defect / fact / classification / metric /
suggestion), every severity mapping, both languages (python / rust), every
suppression state surfaced in metadata, and the scanned-paths reconciliation
list — so a silent change to ANY of those wire shapes reds.

WARDLINE IS THE AUTHORITY for this seam — it OWNS the scan-results body via
``wardline.core.filigree_emit.build_scan_results_body``. That makes the two-sided
protection a two-layer affair (mirroring the suppression-filter contract):

* Layer-1 (``test_golden_matches_blob_pin``): a git-blob byte-pin on the vendored
  golden, so any silent edit to the shared wire reds the default PR suite. On its
  OWN this is CIRCULAR — wardline pins wardline's own bytes.
* Producer-source recheck (``test_golden_matches_live_producer``): the non-circular
  break. It imports wardline's LIVE runtime ``build_scan_results_body`` and asserts
  the body it regenerates from the SAME fixed inputs EQUALS the frozen golden. The
  frozen bytes are tied to the live producer, so if the producer's wire shape drifts
  from the golden (a key renamed/added/dropped, a mapping changed) without a
  re-vendor, it reds even though the byte-pin still passes.

RE-VENDOR PROCEDURE: if you deliberately change the wire (e.g. add a finding wire
field), regenerate the golden from the producer with the SAME inputs below,
recompute the blob SHA and update ``UPSTREAM_BLOB_SHA`` in the SAME commit — the
producer-source recheck will otherwise red.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from wardline.core.filigree_emit import build_scan_results_body
from wardline.core.finding import Finding, Kind, Location, Maturity, Severity, SuppressionState

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "wardline-scan-results-wire.golden.json"

# Layer-1 byte-pin: the git-blob SHA-1 of wardline-scan-results-wire.golden.json.
# Recomputed below as hashlib.sha1(b"blob %d\0" % len(data) + data). Any edit to the
# vendored golden without a matching re-pin reds the default PR suite.
UPSTREAM_BLOB_SHA = "164404bea8a8c29eec9814156441c38a098b9fc8"

# The fixed, deterministic inputs the golden is generated from. Held here so the
# producer-source recheck regenerates the EXACT same body. Covers every Kind,
# severity, language, and suppression state.
FINDINGS = (
    Finding(
        rule_id="PY-WL-101",
        message="untrusted value reaches trusted sink",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/app/handler.py", line_start=12, line_end=14, col_start=4, col_end=20),
        fingerprint="a" * 64,
        suggestion="validate at the boundary before the sink",
        qualname="app.handler.handle",
        confidence=0.9,
        related_entities=("python:function:app.handler.read_raw",),
        properties={"sink": "os.system", "tier": "untrusted"},
    ),
    Finding(
        rule_id="RS-WL-108",
        message="tainted data flows to command execution",
        severity=Severity.CRITICAL,
        kind=Kind.DEFECT,
        location=Location(path="src/main.rs", line_start=42, line_end=42),
        fingerprint="b" * 64,
        qualname="main::run",
    ),
    Finding(
        rule_id="WLN-BOUNDARY-FACT",
        message="external boundary detected",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="src/app/io.py", line_start=3, line_end=3),
        fingerprint="c" * 64,
        qualname="app.io.fetch",
    ),
    Finding(
        rule_id="PY-WL-120",
        message="boundary classification",
        severity=Severity.INFO,
        kind=Kind.CLASSIFICATION,
        location=Location(path="src/app/io.py", line_start=7, line_end=7),
        fingerprint="d" * 64,
        qualname="app.io.fetch",
        suppressed=SuppressionState.WAIVED,
        suppression_reason="reviewed false positive",
    ),
    Finding(
        rule_id="WLN-METRIC-COVERAGE",
        message="decorator coverage 80%",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="src/app/io.py", line_start=1),
        fingerprint="e" * 64,
        properties={"coverage": 0.8},
    ),
    Finding(
        rule_id="PY-WL-126",
        message="consider narrowing the boundary",
        severity=Severity.WARN,
        kind=Kind.SUGGESTION,
        location=Location(path="src/app/util.py", line_start=30, line_end=33),
        fingerprint="f" * 64,
        suggestion="annotate @external_boundary",
        qualname="app.util.helper",
        suppressed=SuppressionState.BASELINED,
        maturity=Maturity.PREVIEW,
    ),
)

SCANNED_PATHS = ("src/app/handler.py", "src/main.rs", "src/app/io.py", "src/app/util.py")


def test_golden_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored golden byte-pins to its git
    blob hash. ANY edit without a matching re-pin reds the default PR suite. On its
    own this pin is wardline-pins-wardline (circular); the non-circular protection is
    ``test_golden_matches_live_producer`` below, which regenerates the body from the
    LIVE producer."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = GOLDEN_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored scan-results wire golden changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, regenerate the golden from build_scan_results_body with the "
        "FINDINGS/SCANNED_PATHS in this module, update UPSTREAM_BLOB_SHA in the same commit, and re-run "
        "conformance (see the RE-VENDOR PROCEDURE at the top of this module); if not, revert the edit."
    )


def test_golden_matches_live_producer() -> None:
    """PRODUCER-SOURCE recheck (non-circular): regenerate the body from wardline's
    LIVE runtime ``build_scan_results_body`` with the SAME fixed inputs and assert it
    EQUALS the frozen golden. This ties the byte-pinned golden to the real producer,
    so a wire-shape drift (a key renamed/added/dropped, a mapping changed) without a
    re-vendor reds even though the byte-pin still passes."""
    golden = json.loads(GOLDEN_PATH.read_text("utf-8"))
    assert build_scan_results_body(FINDINGS, scan_source="wardline", scanned_paths=SCANNED_PATHS) == golden
