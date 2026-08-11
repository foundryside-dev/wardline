"""Freeze the wardline-attest-2 PRODUCER contract: the boundary key set and schema tag
warpline's risk-as-verification consumer keys on. A change here is a deliberate contract
bump (and must update docs/contracts/wardline-attest-2.md + warpline's consumer)."""

from __future__ import annotations

from pathlib import Path

from wardline.core.attest import ACCEPTED_ATTEST_SCHEMAS, ATTEST_SCHEMA, build_attestation

_KEY = "0" * 64

_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "@external_boundary\n"
    "def src():\n"
    "    return object()\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
)

_FROZEN_BOUNDARY_KEYS = {"qualname", "sei", "content_hash", "verdict", "tier"}
_FROZEN_VERDICTS = {"clean", "defect", "unknown"}


def test_attest_schema_tag_frozen() -> None:
    assert ATTEST_SCHEMA == "wardline-attest-2"


def test_boundary_shape_frozen(tmp_path: Path) -> None:
    from datetime import date

    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    bundle = build_attestation(tmp_path, _KEY, today=date(2026, 6, 24))
    for b in bundle["payload"]["boundaries"]:
        assert set(b.keys()) == _FROZEN_BOUNDARY_KEYS
        assert b["verdict"] in _FROZEN_VERDICTS


def test_consumer_contract_doc_exists() -> None:
    doc = Path(__file__).resolve().parents[2] / "docs" / "contracts" / "wardline-attest-2.md"
    assert doc.is_file(), "publish the wardline-attest-2 consumer contract"


def test_accepted_schemas_are_frozen_literals() -> None:
    """The EMITTED tag stays v2 while the ACCEPTED set dual-reads v2+v3.

    The accepted set is written as literals in source so that bumping ATTEST_SCHEMA in
    S1 cannot silently drop v2 from it; this pin freezes both halves independently.
    """
    assert ATTEST_SCHEMA == "wardline-attest-2"
    assert ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")
    # The emitted tag must be a member of the accepted set — a builder that emitted a
    # tag its own verifier rejects would be a self-inconsistent contract.
    assert ATTEST_SCHEMA in ACCEPTED_ATTEST_SCHEMAS


def test_attest_3_contract_doc_states_its_draft_terms() -> None:
    """Pin the v3 contract's CONTENT, not its existence.

    An ``is_file()`` check passes on an empty file. These are the claims a consumer
    reads the document for: that it is a non-emitting draft, that the two verification
    profiles are distinguished, and that the shared vector and its test-only key are
    named. Blank any of those sections and this reds.
    """
    doc = Path(__file__).resolve().parents[2] / "docs" / "contracts" / "wardline-attest-3.md"
    assert doc.is_file(), "publish the wardline-attest-3 consumer contract"
    text = doc.read_text(encoding="utf-8")
    for required in (
        "wardline-attest-3",
        "DRAFT",  # status: Wardline does not emit v3 yet
        "Rollout Fence",  # the gate that governs when it may
        "schema_recognized",  # the dual-read field the verifier reports
        "signature_verified: false",  # the Warpline runtime's always-false profile
        "tests/conformance/fixtures/wardline-attest-3.vector.json",  # the shared vector
        "wardline-attest-3-conformance-vector-key",  # the public, test-only key
    ):
        assert required in text, f"wardline-attest-3.md must state {required!r}"
