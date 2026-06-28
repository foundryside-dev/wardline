"""Phase 5 — ``delta_scope.DeltaScopeReport`` + ``BOUNDARY_CAVEAT`` (spec §5.4)."""

from __future__ import annotations

from wardline.core.delta_scope import BOUNDARY_CAVEAT, DeltaScopeReport, parse_affected_scope


def _delta_report(**overrides: object) -> DeltaScopeReport:
    base: dict[str, object] = {
        "mode": "delta",
        "gate_authority": "advisory",
        "scope_source": "reverify_worklist_v1",
        "entities_requested": 3,
        "files_discovered": 10,
        "files_analyzed": 2,
        "in_scope_findings": 1,
        "fell_back_count": 1,
        "stale_sei_count": 0,
        "unresolved_entities": (),
        "loomweave_used": True,
    }
    base.update(overrides)
    return DeltaScopeReport(**base)  # type: ignore[arg-type]


def test_boundary_caveat_is_the_fixed_stronger_string() -> None:
    """The caveat is the exact (stronger) string and names the in-scope-correctness
    hazard — a finding ON an analyzed entity can be MISSING, not just out-of-scope
    entities omitted."""
    assert BOUNDARY_CAVEAT == (
        "Delta scan analyzes only files containing the affected entities. Findings here "
        "may be incomplete OR absent: cross-file taint whose source lies outside the "
        "analyzed set is not computed, so an in-scope entity can read clean without being "
        "clean. Advisory inner-loop signal, not a verdict — the full scan is the gate of "
        "record."
    )
    # names the in-scope-entity correctness hazard (not just omission)
    assert "incomplete OR absent" in BOUNDARY_CAVEAT
    assert "read clean without being" in BOUNDARY_CAVEAT
    assert "gate of record" in BOUNDARY_CAVEAT


def test_boundary_caveat_is_the_default() -> None:
    report = _delta_report()
    assert report.boundary_caveat == BOUNDARY_CAVEAT


def test_to_dict_keys_and_shape() -> None:
    report = _delta_report(
        unresolved_entities=(
            {"locator": "python:function:pkg.bogus", "sei": None},
            {"locator": None, "sei": "loomweave:eid:gone"},
        ),
    )
    d = report.to_dict()
    assert set(d.keys()) == {
        "mode",
        "gate_authority",
        "scope_source",
        "entities_requested",
        "files_discovered",
        "files_analyzed",
        "in_scope_findings",
        "fell_back_count",
        "stale_sei_count",
        "unresolved_entities",
        "loomweave_used",
        "producer_completeness",
        "boundary_caveat",
    }
    assert d["mode"] == "delta"
    assert d["gate_authority"] == "advisory"
    assert d["scope_source"] == "reverify_worklist_v1"
    assert d["entities_requested"] == 3
    assert d["files_discovered"] == 10
    assert d["files_analyzed"] == 2
    assert d["in_scope_findings"] == 1
    assert d["fell_back_count"] == 1
    assert d["stale_sei_count"] == 0
    assert d["loomweave_used"] is True
    assert d["boundary_caveat"] == BOUNDARY_CAVEAT
    assert d["producer_completeness"] is None
    assert d["unresolved_entities"] == [
        {"locator": "python:function:pkg.bogus", "sei": None},
        {"locator": None, "sei": "loomweave:eid:gone"},
    ]


def test_to_dict_unresolved_entities_are_copies() -> None:
    """``to_dict`` copies each inner dict so mutating the output does not corrupt the
    frozen report."""
    original = {"locator": "python:function:pkg.x", "sei": None}
    report = _delta_report(unresolved_entities=(original,))
    d = report.to_dict()
    unresolved = d["unresolved_entities"]
    assert isinstance(unresolved, list)
    unresolved[0]["locator"] = "MUTATED"
    assert original["locator"] == "python:function:pkg.x"


def test_delta_mode_gate_authority_is_advisory() -> None:
    report = _delta_report(mode="delta", gate_authority="advisory")
    assert report.to_dict()["gate_authority"] == "advisory"


def test_full_fallback_mode_gate_authority_is_gate_of_record() -> None:
    """In full-fallback the scan IS the gate of record — machine-readable distinction
    from an advisory delta pass."""
    report = _delta_report(
        mode="full-fallback",
        gate_authority="gate-of-record",
        files_analyzed=10,  # == files_discovered in full-fallback
    )
    d = report.to_dict()
    assert d["mode"] == "full-fallback"
    assert d["gate_authority"] == "gate-of-record"
    assert d["files_analyzed"] == d["files_discovered"]


def test_stale_sei_and_fell_back_counts_surface_trust() -> None:
    report = _delta_report(fell_back_count=2, stale_sei_count=1)
    d = report.to_dict()
    assert d["fell_back_count"] == 2
    assert d["stale_sei_count"] == 1


# --- A1: AffectedScope.producer_completeness ---

_SAMPLE_IC = {
    "status": "partial",
    "as_of": "2026-06-18T00:00:00+00:00",
    "graph_fresh": True,
    "graph_ref": "e5b022a65a74759344e67538a0bb823b64c843ad",
    "depth_capped": True,
    "unresolved_count": 0,
    "reasons": ["depth_capped"],
}


def test_worklist_captures_impact_completeness() -> None:
    payload = {
        "schema": "warpline.reverify_worklist.v1",
        "data": {
            "impact_completeness": _SAMPLE_IC,
            "items": [{"entity": {"locator": "python:function:a.alpha", "sei": None}}],
        },
    }
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.producer_completeness == _SAMPLE_IC


def test_worklist_missing_impact_completeness_returns_none() -> None:
    payload = {
        "schema": "warpline.reverify_worklist.v1",
        "data": {
            "items": [{"entity": {"locator": "python:function:a.alpha", "sei": None}}],
        },
    }
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.producer_completeness is None


def test_worklist_non_dict_impact_completeness_returns_none() -> None:
    """A non-dict value for impact_completeness is treated as absent (defensive capture)."""
    payload = {
        "schema": "warpline.reverify_worklist.v1",
        "data": {
            "impact_completeness": "not-a-dict",
            "items": [{"entity": {"locator": "python:function:a.alpha", "sei": None}}],
        },
    }
    scope = parse_affected_scope(payload)
    assert scope.producer_completeness is None


def test_entity_list_has_no_producer_completeness() -> None:
    scope = parse_affected_scope([{"locator": "python:function:a.alpha"}])
    assert scope.source_kind == "entity_list"
    assert scope.producer_completeness is None


# --- A2: DeltaScopeReport scope_source + producer_completeness ---


def _report(**overrides: object) -> DeltaScopeReport:
    base: dict[str, object] = dict(
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
        producer_completeness=_SAMPLE_IC,
    )
    base.update(overrides)
    return DeltaScopeReport(**base)  # type: ignore[arg-type]


def test_report_serializes_scope_source_and_producer_completeness() -> None:
    d = _report().to_dict()
    assert d["scope_source"] == "reverify_worklist_v1"
    assert d["producer_completeness"] == _SAMPLE_IC
    assert set(d) >= {"scope_source", "producer_completeness"}


def test_report_producer_completeness_defaults_none() -> None:
    d = _report(producer_completeness=None, scope_source="entity_list").to_dict()
    assert d["producer_completeness"] is None
    assert d["scope_source"] == "entity_list"
