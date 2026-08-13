"""Consumer-first dual-read for wardline-attest-3 (declaration-surface-v2 §13.1 item 2).

Wardline still EMITS attest-2 (the freeze test pins that). This suite proves the
verifier RECOGNISES attest-3 — schema recognition is split out of
signature_valid so an attest-3 bundle is distinguishable from a bad key or a
tampered payload — and freezes the shared attest-3 vector warpline vendors."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# CROSS-TASK GATE — DO NOT SIMPLIFY (see this task's "Cross-task dependency" note).
# Task 23's seam-registry gate greps THIS FILE's source text. The `_sign as
# sign_artifact` alias, the `GOLDEN_KEY` name and the `*_FIELD` constants below are
# each load-bearing to that grep; inlining any of them reds Task 23.
from wardline.core.attest import (
    ACCEPTED_ATTEST_SCHEMAS,
    ATTEST_SCHEMA,
    verify_attestation,
)
from wardline.core.attest import (
    _sign as sign_artifact,
)

VECTOR = Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json"
SCHEMA_FIELD = "schema"
PAYLOAD_FIELD = "payload"
SIGNATURE_FIELD = "signature"
# Public, test-only key — a conformance artifact, never an operational secret.
GOLDEN_KEY = "wardline-attest-3-conformance-vector-key"


def _bundle() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_accepted_schemas_are_pinned() -> None:
    assert ATTEST_SCHEMA == "wardline-attest-2"  # S0 emits v2, unchanged
    assert ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")


def test_attest_3_vector_signature_is_internally_consistent() -> None:
    bundle = _bundle()
    assert bundle[SCHEMA_FIELD] == "wardline-attest-3"
    expected = sign_artifact(bundle[PAYLOAD_FIELD], GOLDEN_KEY, schema=bundle[SCHEMA_FIELD])
    assert bundle[SIGNATURE_FIELD]["value"] == expected["value"]


# ---- the six-case recognition/validity matrix ----


# ---- the preview's shape agrees with the live producer (wardline-b59cbea4bc) ----
#
# The vector is what S1's producer preflight byte- and semantic-compares its first
# real attest-3 output against (§13.3). A preview that contradicts the live payload
# cannot be reproduced without shipping the wrong shape, so these pin the agreement
# rather than the bytes. They compute the expected key set from AssurancePosture
# instead of transcribing it — transcription is precisely how the stub got in.


def test_attest_3_vector_posture_is_the_live_posture_plus_declaration_debt() -> None:
    from wardline.core.assure import AssurancePosture

    live_keys = set(
        AssurancePosture(
            boundaries_total=0, proven=0, defect_total=0, unknown=[], engine_limited=0,
            coverage_pct=None, unanalyzed_total=0, unanalyzed_rule_ids=[], waiver_debt=[],
            baselined_total=0, judged_total=0,
        ).to_dict()
    )
    posture = _bundle()[PAYLOAD_FIELD]["posture"]
    # §11.2 puts declaration debt IN the posture — one home, no top-level sibling.
    assert set(posture) == live_keys | {"declaration_debt"}
    assert "declaration_debt" not in _bundle()[PAYLOAD_FIELD]
    # `unknown` is a LIST OF OBJECTS (UnknownBoundary.to_dict()), never a count —
    # the single most misread key in this payload.
    assert all(isinstance(u, dict) and "location" in u for u in posture["unknown"])
    assert posture["proven"] + posture["defect_total"] + len(posture["unknown"]) == posture["boundaries_total"]


def test_attest_3_vector_posture_and_boundaries_describe_the_same_scan() -> None:
    # attest.py builds `boundaries` and `posture` from ONE scan over the same
    # declared_qualnames, so a preview whose counters outrun its boundary rows is
    # describing a scan that cannot exist.
    payload = _bundle()[PAYLOAD_FIELD]
    verdicts = [b["verdict"] for b in payload["boundaries"]]
    posture = payload["posture"]
    assert posture["boundaries_total"] == len(verdicts)
    assert posture["proven"] == verdicts.count("clean")
    assert posture["defect_total"] == verdicts.count("defect")
    assert len(posture["unknown"]) == verdicts.count("unknown")
    assert {u["qualname"] for u in posture["unknown"]} == {
        b["qualname"] for b in payload["boundaries"] if b["verdict"] == "unknown"
    }
    assert payload["boundaries"] == sorted(payload["boundaries"], key=lambda b: b["qualname"])


def test_attest_3_vector_declaration_vocabulary_is_self_consistent() -> None:
    payload = _bundle()[PAYLOAD_FIELD]
    counts = payload["declaration_counts"]
    for declaration in payload["declarations"]:
        # PLURAL family token in the singular `kind` field: the ledger and the
        # counters share one vocabulary, so a consumer can group one by the other.
        assert declaration["kind"] in counts, declaration["kind"]
        # §11.1's three classes. `machine_verified` on a facet is the specific
        # error this pin exists for: §7's emitted-text discipline forbids claiming
        # wardline verified the legal record. Whether a facet is
        # `recorded_unverified` or `structurally_verified` is an OPEN S1 ruling —
        # change this line deliberately, with the ruling, not in passing.
        assert declaration["verification_class"] in {
            "machine_verified", "structurally_verified", "recorded_unverified"
        }
        if declaration["kind"] == "facets":
            assert declaration["verification_class"] == "recorded_unverified"
    for kind, total in counts.items():
        assert total == sum(1 for d in payload["declarations"] if d["kind"] == kind), kind
    # every declared subject is a boundary this same scan reports on
    assert {d["subject"] for d in payload["declarations"]} <= {b["qualname"] for b in payload["boundaries"]}


def test_valid_v3_is_recognised_and_valid() -> None:
    report = verify_attestation(_bundle(), GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True


def test_wrong_key_is_recognised_but_invalid() -> None:
    report = verify_attestation(_bundle(), "not-the-vector-key")
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_tampered_v3_is_recognised_but_invalid() -> None:
    bundle = _bundle()
    bundle["payload"]["commit"] = "0" * 40
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_correctly_resigned_unknown_schema_is_unrecognised() -> None:
    # THE case the split exists for: _sign binds the bundle's own recorded
    # schema tag, so a wardline-attest-9 bundle re-signed with the RIGHT key
    # over its own tag has a matching HMAC — recognition is the only thing
    # separating it from a real bundle. Both flags must be False.
    bundle = _bundle()
    bundle["schema"] = "wardline-attest-9"
    bundle["signature"] = sign_artifact(bundle["payload"], GOLDEN_KEY, schema="wardline-attest-9")
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_missing_schema_is_unrecognised() -> None:
    bundle = _bundle()
    del bundle["schema"]
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_attest_2_bundles_still_verify_with_the_new_key_present() -> None:
    payload = {"wardline_version": "1.5.0", "attested_at": "2026-08-09", "commit": None, "dirty": False}
    bundle = {"schema": ATTEST_SCHEMA, "payload": payload, "signature": sign_artifact(payload, GOLDEN_KEY)}
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True
    assert set(report) == {"schema_recognized", "signature_valid", "reproduced", "mismatches", "note"}


def test_vendored_warpline_copy_is_byte_identical_when_present() -> None:
    # Layer-2 cross-repo drift check (the loomweave descriptor-golden pattern):
    # Coordinated/release jobs arm this comparison with WARPLINE_REPO; a normal
    # standalone Wardline checkout may skip when the sibling is absent.
    configured_repo = os.environ.get("WARPLINE_REPO")
    repo = configured_repo or "/home/john/warpline"
    vendored = Path(repo) / "tests" / "fixtures" / "wardline-attest-3.vector.json"
    if not vendored.exists():
        if configured_repo is not None:
            pytest.fail(f"missing required Warpline receipt at {vendored}")
        pytest.skip(f"Warpline checkout not present at {vendored}; Task 23 supplies WARPLINE_REPO")
    assert vendored.read_bytes() == VECTOR.read_bytes()
