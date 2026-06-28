"""Freeze the wardline-attest-2 PRODUCER contract: the boundary key set and schema tag
warpline's risk-as-verification consumer keys on. A change here is a deliberate contract
bump (and must update docs/contracts/wardline-attest-2.md + warpline's consumer)."""

from __future__ import annotations

from pathlib import Path

from wardline.core.attest import ATTEST_SCHEMA, build_attestation

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
