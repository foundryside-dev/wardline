"""Guard the 80e457bc41-class drift: the hand-maintained MCP scope schema must stay
key-identical to DeltaScopeReport.to_dict(). A field added to one but not the other
silently desyncs structuredContent from the payload."""

from __future__ import annotations

from wardline.core.delta_scope import DeltaScopeReport
from wardline.mcp.server import _SCAN_OUTPUT_SCHEMA


def _sample_report() -> DeltaScopeReport:
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
    )


def test_scope_schema_properties_match_report_keys() -> None:
    report_keys = set(_sample_report().to_dict().keys())
    schema_keys = set(_SCAN_OUTPUT_SCHEMA["properties"]["scope"]["properties"].keys())
    assert schema_keys == report_keys


def test_scope_schema_required_matches_report_keys() -> None:
    report_keys = set(_sample_report().to_dict().keys())
    required = set(_SCAN_OUTPUT_SCHEMA["properties"]["scope"]["required"])
    assert required == report_keys
