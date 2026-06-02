# tests/unit/core/test_dossier_assembler.py
"""T4.2 — the dossier assembler skeleton.

Composes Wardline's OWN taint posture for REAL, plus Clarion structure/linkages
and Filigree open work via STUBS behind clean source-provider seams. When a source
is absent/unreachable it emits an HONEST PARTIAL envelope (that section marked
unavailable) — never fabricated, never a crash. The SEI is an OPAQUE input the
envelope is keyed on (resolution is Track 3's lane, not Track 4's).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.clarion.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.dossier import (
    DOSSIER_TOKEN_BUDGET,
    LinkagesSection,
    WorkSection,
    build_dossier,
    estimate_tokens,
)
from wardline.core.errors import DossierError

# A @trusted producer that leaks an external-boundary value → PY-WL-101 fires.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "def mid(p):\n    return read_raw(p)\n"
    "@trusted\ndef leaky(p):\n    return mid(p)\n"
)


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


# --- self / trust posture is REAL -------------------------------------------


def test_self_trust_posture_is_real(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    assert d.identity.qualname == "svc.leaky"
    assert d.identity.kind == "function"
    assert d.identity.path == "svc.py"
    assert d.identity.line_start == 8
    # declared @trusted → INTEGRAL; actual return is less trusted → the defect
    assert d.trust.declared_return == "INTEGRAL"
    assert d.trust.actual_return is not None and d.trust.actual_return != "INTEGRAL"
    assert d.trust.gate_verdict == "defect"
    assert any(f.rule_id == "PY-WL-101" for f in d.trust.active_findings)


def test_clean_entity_has_clean_verdict_and_no_findings(tmp_path: Path) -> None:
    d = build_dossier("svc.read_raw", root=_proj(tmp_path))
    assert d.trust.gate_verdict == "clean"
    assert d.trust.active_findings == []


def test_shape_section_carries_signature_and_decorators(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    assert d.shape.signature is not None and "p" in d.shape.signature
    assert any("trusted" in dec for dec in d.shape.decorators)


def test_signature_includes_return_annotation_when_declared(tmp_path: Path) -> None:
    proj = tmp_path / "ann"
    proj.mkdir()
    (proj / "m.py").write_text("def f(x: int) -> str:\n    return str(x)\n", encoding="utf-8")
    d = build_dossier("m.f", root=proj)
    assert d.shape.signature == "(x: int) -> str"


# --- honest partial: stubbed sources are unavailable, not fabricated --------


def test_default_assembly_is_honest_partial(tmp_path: Path) -> None:
    # No Clarion / Filigree providers configured → those sections are unavailable
    # WITH a reason, while self/shape/trust are intact. No crash, no fabrication.
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    assert d.linkages.available is False
    assert d.linkages.reason is not None
    assert d.linkages.callers == [] and d.linkages.callees == []
    assert d.work.available is False
    assert d.work.reason is not None
    assert d.work.tickets == []
    # the self sections still present
    assert d.trust.gate_verdict == "defect"


# --- SEI is an opaque key supplied as input ---------------------------------


def test_sei_is_carried_verbatim_as_the_opaque_key(tmp_path: Path) -> None:
    weird = "clarion:eid:UNUSUAL-Token_With.Punct/0xFF"
    binding = EntityBinding(
        locator="svc.leaky",
        sei=weird,
        identity=IdentityStatus.ALIVE,
        content=ContentStatus.STALE,
        content_hash="abc",
    )
    d = build_dossier("svc.leaky", root=_proj(tmp_path), binding=binding)
    assert d.identity.sei == weird  # verbatim, never parsed/normalised
    assert d.identity.keyed_on_sei is True
    assert d.identity.identity_status is IdentityStatus.ALIVE
    assert d.identity.content_status is ContentStatus.STALE
    assert d.identity.content_hash == "abc"


def test_no_binding_means_unavailable_identity_axes(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    assert d.identity.sei is None
    assert d.identity.keyed_on_sei is False
    assert d.identity.identity_status is IdentityStatus.UNAVAILABLE
    assert d.identity.content_status is ContentStatus.UNKNOWN


# --- error model: entity not found is a tool-execution fault -----------------


def test_unknown_entity_raises_dossier_error(tmp_path: Path) -> None:
    with pytest.raises(DossierError):
        build_dossier("svc.does_not_exist", root=_proj(tmp_path))


# --- a provider that ERRORS degrades to honest-partial (no crash) -----------


class _BoomLinkages:
    def linkages(self, binding: EntityBinding) -> LinkagesSection:
        raise RuntimeError("clarion unreachable: connection refused")


class _SilentLinkages:
    def linkages(self, binding: EntityBinding) -> LinkagesSection | None:
        return None  # the provider has no opinion for this entity


def test_provider_no_opinion_degrades_to_unavailable(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path), linkage_provider=_SilentLinkages())
    assert d.linkages.available is False
    assert d.linkages.reason == "source returned no data"


def test_provider_failure_degrades_to_unavailable(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path), linkage_provider=_BoomLinkages())
    assert d.linkages.available is False
    assert d.linkages.reason is not None
    assert "clarion unreachable" in d.linkages.reason
    # the rest of the envelope is intact — the call SUCCEEDED
    assert d.trust.gate_verdict == "defect"


# --- a working stub provider proves the seam (T4.3 wiring drops in) ----------


class _FakeLinkages:
    def linkages(self, binding: EntityBinding) -> LinkagesSection:
        return LinkagesSection(
            available=True,
            callers=["svc.caller_a"],
            callees=["svc.mid"],
            scc_peers=[],
            identity_status=IdentityStatus.ALIVE,
            content_status=ContentStatus.FRESH,
            reason=None,
        )


class _FakeWork:
    def work(self, binding: EntityBinding) -> WorkSection:
        from wardline.core.dossier import TicketRef

        return WorkSection(
            available=True,
            tickets=[TicketRef(issue_id="wardline-1", status="open", priority="P1", title="fix")],
            identity_status=IdentityStatus.ALIVE,
            content_status=ContentStatus.FRESH,
            reason=None,
        )


def test_stub_providers_fill_their_sections(tmp_path: Path) -> None:
    binding = EntityBinding(locator="svc.leaky", sei="clarion:eid:x", identity=IdentityStatus.ALIVE)
    d = build_dossier(
        "svc.leaky",
        root=_proj(tmp_path),
        binding=binding,
        linkage_provider=_FakeLinkages(),
        work_provider=_FakeWork(),
    )
    assert d.linkages.available is True
    assert d.linkages.callers == ["svc.caller_a"]
    assert d.work.available is True
    assert d.work.tickets[0].issue_id == "wardline-1"


# --- the assembled envelope is token-bounded --------------------------------


def test_assembled_envelope_is_token_bounded(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    text = json.dumps(d.to_dict(), sort_keys=True)
    assert estimate_tokens(text) <= DOSSIER_TOKEN_BUDGET


# --- synthesis is best-effort and degrades with its inputs ------------------


def test_synthesis_is_present_and_degrades_without_optional_sources(tmp_path: Path) -> None:
    d = build_dossier("svc.leaky", root=_proj(tmp_path))
    # best-effort: mentions the live defect; never asserts a join it could not compute
    assert d.synthesis is not None
    assert "PY-WL-101" in d.synthesis
