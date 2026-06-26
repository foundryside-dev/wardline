"""Drift-check DeltaScopeReport.to_dict() against the published wardline.delta_scope.v1
contract. A new/removed field here is a deliberate contract change — bump the artifact."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.delta_scope import DeltaScopeReport

_CONTRACT = Path(__file__).resolve().parent / "wardline_delta_scope_contract.v1.json"


def _sample() -> dict[str, object]:
    return DeltaScopeReport(
        mode="delta",
        gate_authority="advisory",
        scope_source="reverify_worklist_v1",
        entities_requested=1,
        files_discovered=1,
        files_analyzed=1,
        in_scope_findings=0,
        fell_back_count=0,
        stale_sei_count=0,
        unresolved_entities=(),
        loomweave_used=False,
        producer_completeness={"status": "partial", "as_of": "2026-06-18T00:00:00+00:00"},
    ).to_dict()


def test_delta_scope_matches_published_contract() -> None:
    contract = json.loads(_CONTRACT.read_text(encoding="utf-8"))
    assert contract["schema"] == "wardline.delta_scope.v1"
    assert set(_sample().keys()) == set(contract["fields"])
