# tests/unit/core/test_dossier_envelope.py
"""T4.1 — the EntityDossier envelope: typed, JSON-serialisable, token-bounded
(<=2k), freshness-stamped on BOTH orthogonal axes (identity x content), SEI-keyed.

These tests pin the SCHEMA and the token discipline only (T4.1). The assembler
that fills sections from real/stubbed sources is T4.2.
"""

from __future__ import annotations

import json

import pytest

from wardline.clarion.identity import ContentStatus, IdentityStatus
from wardline.core.dossier import (
    DOSSIER_TOKEN_BUDGET,
    ElidedSection,
    EntityDossier,
    FindingRef,
    IdentitySection,
    LinkagesSection,
    ShapeSection,
    TicketRef,
    Truncation,
    TrustSection,
    WorkSection,
    bound_to_budget,
    estimate_tokens,
)


def _identity(**over: object) -> IdentitySection:
    base: dict[str, object] = dict(
        qualname="mod.fn",
        kind="function",
        path="src/mod.py",
        line_start=10,
        line_end=20,
        sei="clarion:eid:abc123",
        keyed_on_sei=True,
        identity_status=IdentityStatus.ALIVE,
        content_status=ContentStatus.FRESH,
        content_hash="deadbeef",
    )
    base.update(over)
    return IdentitySection(**base)  # type: ignore[arg-type]


def _minimal_dossier(**over: object) -> EntityDossier:
    base: dict[str, object] = dict(
        identity=_identity(),
        shape=ShapeSection(signature="(x: int) -> str", decorators=["@trusted(INTEGRAL)"]),
        trust=TrustSection(
            declared_return="INTEGRAL",
            actual_return="ASSURED",
            gate_verdict="defect",
            active_findings=[FindingRef(rule_id="PY-WL-101", severity="ERROR", message="leak", line=12)],
        ),
        linkages=LinkagesSection.unavailable("clarion not configured"),
        work=WorkSection.unavailable("filigree not configured"),
        synthesis=None,
        truncation=Truncation.none(),
    )
    base.update(over)
    return EntityDossier(**base)  # type: ignore[arg-type]


# --- schema / serialization -------------------------------------------------


def test_envelope_is_json_serialisable_via_to_dict() -> None:
    d = _minimal_dossier()
    blob = d.to_dict()
    # must survive a real json round-trip (no enums/dataclasses leaking through)
    text = json.dumps(blob, sort_keys=True)
    again = json.loads(text)
    assert again["identity"]["qualname"] == "mod.fn"
    assert again["trust"]["active_findings"][0]["rule_id"] == "PY-WL-101"


def test_envelope_is_keyed_on_the_opaque_sei() -> None:
    d = _minimal_dossier()
    assert d.identity.sei == "clarion:eid:abc123"
    assert d.identity.keyed_on_sei is True
    assert d.to_dict()["identity"]["sei"] == "clarion:eid:abc123"


# --- two orthogonal freshness axes -----------------------------------------


@pytest.mark.parametrize(
    "ident,content",
    [
        (IdentityStatus.ALIVE, ContentStatus.FRESH),
        (IdentityStatus.ALIVE, ContentStatus.STALE),
        (IdentityStatus.ORPHANED, ContentStatus.FRESH),
        (IdentityStatus.ORPHANED, ContentStatus.STALE),
        (IdentityStatus.UNAVAILABLE, ContentStatus.UNKNOWN),
    ],
)
def test_both_freshness_axes_are_independent_and_surfaced(ident: IdentityStatus, content: ContentStatus) -> None:
    # Every (identity, content) combination must be representable WITHOUT one being
    # inferred from the other — the spec is emphatic both are always surfaced.
    sec = _identity(identity_status=ident, content_status=content)
    blob = sec  # access via to_dict at the envelope level
    d = _minimal_dossier(identity=blob)
    out = d.to_dict()["identity"]
    assert out["identity_status"] == ident.value
    assert out["content_status"] == content.value


def test_unavailable_section_carries_a_reason_and_marks_both_axes_unknown() -> None:
    sec = LinkagesSection.unavailable("clarion not configured")
    assert sec.available is False
    assert sec.reason == "clarion not configured"
    assert sec.identity_status is IdentityStatus.UNAVAILABLE
    assert sec.content_status is ContentStatus.UNKNOWN


# --- token estimator: deterministic + conservative -------------------------


def test_estimate_tokens_is_deterministic() -> None:
    text = json.dumps(_minimal_dossier().to_dict(), sort_keys=True)
    assert estimate_tokens(text) == estimate_tokens(text)


def test_estimate_tokens_empty_is_zero() -> None:
    assert estimate_tokens("") == 0


def test_estimate_tokens_over_counts_relative_to_chars_over_four() -> None:
    # The estimator must NOT under-count vs the naive chars/4 rule of thumb — for a
    # fail-closed tool, under-counting lets an over-budget envelope through unlabeled
    # (false-green). Conservative == estimate >= chars/4 always.
    for text in ['{"qualname": "a.b.c", "x": [1, 2, 3]}', "a" * 100, "x " * 50]:
        assert estimate_tokens(text) >= len(text) // 4


# --- token budget: explicit, marked truncation (the false-green guard) ------


def test_small_envelope_is_under_budget_and_not_truncated() -> None:
    bounded = bound_to_budget(_minimal_dossier())
    assert bounded.truncation.truncated is False
    assert bounded.truncation.elided == []
    text = json.dumps(bounded.to_dict(), sort_keys=True)
    assert estimate_tokens(text) <= DOSSIER_TOKEN_BUDGET


def test_oversized_envelope_is_bounded_and_explicitly_marked() -> None:
    # Build an envelope whose content WOULD blow the 2k budget: a flood of findings
    # plus huge linkage lists. The budgeting must trim AND surface an honest marker.
    findings = [FindingRef(rule_id=f"PY-WL-{i:03d}", severity="ERROR", message="x" * 80, line=i) for i in range(400)]
    callers = [f"pkg.module{i}.caller_function_{i}" for i in range(400)]
    big = _minimal_dossier(
        trust=TrustSection(
            declared_return="INTEGRAL",
            actual_return="EXTERNAL_RAW",
            gate_verdict="defect",
            active_findings=findings,
        ),
        linkages=LinkagesSection(
            available=True,
            callers=callers,
            callees=[],
            scc_peers=[],
            identity_status=IdentityStatus.ALIVE,
            content_status=ContentStatus.FRESH,
            reason=None,
        ),
    )
    # precondition: it really is over budget before bounding
    assert estimate_tokens(json.dumps(big.to_dict(), sort_keys=True)) > DOSSIER_TOKEN_BUDGET

    bounded = bound_to_budget(big)

    # (a) now under budget
    text = json.dumps(bounded.to_dict(), sort_keys=True)
    assert estimate_tokens(text) <= DOSSIER_TOKEN_BUDGET
    # (b) truncation is EXPLICIT and elision is honest (reports shown-of-total)
    assert bounded.truncation.truncated is True
    assert bounded.truncation.elided, "must name which sections were trimmed"
    by_section = {e.section: e for e in bounded.truncation.elided}
    assert "trust.active_findings" in by_section
    elided = by_section["trust.active_findings"]
    assert elided.total == 400
    assert elided.shown == len(bounded.trust.active_findings)
    assert elided.shown < elided.total


def test_budget_never_drops_the_identity_section() -> None:
    # Identity (the SEI key + freshness) is the load-bearing minimum: budgeting trims
    # lists, never the entity's identity. A huge synthesis string must not erase it.
    big = _minimal_dossier(synthesis="z" * 50_000)
    bounded = bound_to_budget(big)
    assert bounded.identity.sei == "clarion:eid:abc123"
    assert bounded.identity.qualname == "mod.fn"
    assert estimate_tokens(json.dumps(bounded.to_dict(), sort_keys=True)) <= DOSSIER_TOKEN_BUDGET
    assert bounded.truncation.truncated is True


def test_oversize_from_synthesis_only_drops_synthesis_with_empty_elision() -> None:
    # Over budget purely because of a huge synthesis, with no lists to trim: the
    # budgeter drops synthesis and reports an honest marker with an EMPTY elision list
    # (nothing was list-trimmed) — the note still says what happened.
    big = _minimal_dossier(
        trust=TrustSection(
            declared_return="INTEGRAL", actual_return="INTEGRAL", gate_verdict="clean", active_findings=[]
        ),
        synthesis="z" * 50_000,
    )
    bounded = bound_to_budget(big)
    assert bounded.truncation.truncated is True
    assert bounded.truncation.elided == []
    assert bounded.synthesis is None
    assert "synthesis" in (bounded.truncation.note or "")
    assert estimate_tokens(json.dumps(bounded.to_dict(), sort_keys=True)) <= DOSSIER_TOKEN_BUDGET


def test_elided_section_shape() -> None:
    e = ElidedSection(section="linkages.callers", shown=5, total=400)
    assert (e.section, e.shown, e.total) == ("linkages.callers", 5, 400)


def test_ticket_ref_shape() -> None:
    t = TicketRef(issue_id="wardline-1", status="open", priority="P1", title="fix it")
    assert t.issue_id == "wardline-1"
