"""G1 cross-member shared vector — the wardline (producer) half, byte-pinned to legis.

legis AUTHORS the canonical Weft conformance vector for the wardline→legis signed
scan-artifact wire at ``legis/tests/contract/weft/vectors/wardline_scan_artifact.v1.json``
and drives its REAL ingest (``active_defects`` / ``verify_wardline_artifact``) over it
(``legis/tests/contract/weft/test_wardline_scan_artifact_contract.py``). This file is the
PRODUCER half: wardline vendors that vector **byte-identical** (the Layer-1 byte-pin
below) and proves wardline's REAL signer (:func:`wl_legis.sign_artifact`) reproduces the
vector's ``expected_signature`` and wardline's REAL projection
(:func:`wl_legis.project_finding`) emits the vector's finding wire shape.

Why this closes G1 (federation-interface audit / Weft incident 2026-06-10, root cause #2):
before this, wardline pinned its own ``legis_scan_wire.golden.json`` and legis pinned its
own ``wardline_scan_artifact.v1.json`` — two INDEPENDENT vendored mirrors that agreed only
by hand. A canonical-JSON or HMAC drift on either side re-signed cleanly and broke the
other invisibly. Now BOTH sides load the SAME bytes: the byte-pin ties wardline's vendored
copy to legis's authored blob, and wardline's live signer must reproduce the byte-exact
``expected_signature`` legis baked in. A divergence stops reproducing the signature HERE,
in CI, instead of routing zero defects under a green ``verified`` status in production.

Two-layer drift discipline (the conformance kit): the byte-pin + signer reproduction run
in the DEFAULT suite (fail-closed offline, no legis checkout needed); the ``Layer-2``
recheck (:func:`test_vendored_vector_matches_legis_source`, marked
``legis_scan_artifact_drift`` and excluded from the default suite) re-compares the vendored
copy to legis's LIVE source so an intentional legis-side vector change is caught at the
release gate rather than silently diverging.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from wardline.core import legis as wl_legis
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState

_VECTOR_PATH = Path(__file__).parent / "vectors" / "wardline_scan_artifact.v1.json"

# Layer-1 byte-pin: the git blob sha1 of legis's canonical vector
# (legis/tests/contract/weft/vectors/wardline_scan_artifact.v1.json @ a clean tree).
# wardline's vendored copy MUST hash identical — that is the proof the two repos load the
# SAME bytes, not two mirrors that drifted apart. Re-pin ONLY in lockstep with an
# intentional legis-side vector change (and re-vendor the bytes in the same commit).
VENDORED_BLOB_SHA = "fd4b21be6f8df15fda37606c65df73fd464b9aea"


def _git_blob_sha1(data: bytes) -> str:
    """The git blob object id of *data* (``sha1("blob <len>\\0" + data)``)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _vector() -> dict:
    return json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))


def _signing_key() -> bytes:
    return _vector()["signing"]["key_utf8"].encode("utf-8")


def test_vendored_vector_is_byte_identical_to_legis_blob_pin() -> None:
    # Runs in the DEFAULT suite: a vendored copy that drifts from legis's authored blob
    # (a hand edit, an accidental reformat) fails closed here without any legis checkout.
    actual = _git_blob_sha1(_VECTOR_PATH.read_bytes())
    assert actual == VENDORED_BLOB_SHA, (
        f"vendored wardline_scan_artifact.v1.json blob {actual} != pinned {VENDORED_BLOB_SHA}; "
        "the wardline copy drifted from legis's canonical vector. Re-vendor byte-identical and "
        "re-pin ONLY in lockstep with the legis hub."
    )


@pytest.mark.parametrize(
    "case",
    [c for c in _vector()["valid"] if "expected_signature" in c],
    ids=lambda c: c["name"],
)
def test_real_signer_reproduces_legis_expected_signature(case: dict) -> None:
    # The non-circular producer-source recheck AND the canonicalization-drift detector:
    # wardline's REAL signer must reproduce the byte-exact cross-impl signature legis baked
    # into the vector. If wardline's canonical-JSON/HMAC formula ever diverges from legis's
    # (enforcement.signing.sign over canonical.py), this stops reproducing — the G1 incident
    # class, caught in CI rather than re-signed clean and broken in the field.
    assert wl_legis.sign_artifact(case["artifact"], _signing_key()) == case["expected_signature"]


def test_real_projection_emits_the_vector_finding_wire_shape() -> None:
    # Tie wardline's REAL projection to the vector's golden finding: a Finding equivalent to
    # the vector's one active defect must project onto exactly the vector's finding wire
    # key-set, with the legis-routing-critical kind/suppression_state values. A per-finding
    # key rename on the producer (the route-to-a-defaulted-key risk) reds here.
    golden = next(c for c in _vector()["valid"] if c["name"] == "golden_single_active_defect")
    vector_finding = golden["artifact"]["findings"][0]
    finding = Finding(
        rule_id=vector_finding["rule_id"],
        message=vector_finding["message"],
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1, line_end=1, col_start=0, col_end=0),
        fingerprint=vector_finding["fingerprint"],
        qualname=vector_finding["qualname"],
        properties=dict(vector_finding["properties"]),
        suppressed=SuppressionState.ACTIVE,
    )
    projected = wl_legis.project_finding(finding)
    assert set(projected) == set(vector_finding), (
        "wardline's projected finding key-set drifted from the shared vector's finding wire"
    )
    assert projected["kind"] == vector_finding["kind"] == "defect"
    assert projected["suppression_state"] == vector_finding["suppression_state"] == "active"
    assert projected["rule_id"] == vector_finding["rule_id"]
    assert projected["fingerprint"] == vector_finding["fingerprint"]
    # The vector's properties are trust-tier-valued, so wardline's tier filter keeps them.
    assert projected["properties"] == vector_finding["properties"]


def _legis_source_vector() -> Path | None:
    candidates: list[Path] = []
    if env := os.environ.get("LEGIS_REPO"):
        candidates.append(Path(env) / "tests" / "contract" / "weft" / "vectors" / "wardline_scan_artifact.v1.json")
    candidates.append(
        Path(__file__).resolve().parents[3]
        / "legis"
        / "tests"
        / "contract"
        / "weft"
        / "vectors"
        / "wardline_scan_artifact.v1.json"
    )
    return next((path for path in candidates if path.exists()), None)


@pytest.mark.legis_scan_artifact_drift
def test_vendored_vector_matches_legis_source() -> None:
    # Layer-2 (release-gate) drift alarm — excluded from the default suite. When a legis
    # checkout is present, the vendored copy must be byte-identical to legis's LIVE source,
    # so an intentional legis-side vector change is caught here rather than silently
    # diverging behind a stale byte-pin.
    source = _legis_source_vector()
    if source is None:
        pytest.skip("legis repo not found; set LEGIS_REPO to enable the cross-repo drift recheck")
    assert _VECTOR_PATH.read_bytes() == source.read_bytes(), (
        "vendored wardline_scan_artifact.v1.json diverged from legis's live source; "
        "re-vendor byte-identical and re-pin VENDORED_BLOB_SHA in the same commit"
    )
