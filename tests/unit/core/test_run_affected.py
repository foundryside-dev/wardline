"""Phase 3 — scan scoping in ``run_scan`` (``--affected`` delta scan).

These tests pin the wiring ``run_scan`` adds between discovery and analysis:

* a scoped subset reaches the analyzer (only affected-entity files are analyzed);
* the full path is unchanged when ``affected is None`` (INV-1) — proven by a spy that
  ``build_qualname_index`` is NOT called on the full-scan path;
* ``affected`` + ``new_since`` together is a loud ``ScopeParseError``;
* in delta mode ``gate_findings`` RETAINS a display-excluded ERROR in an analyzed file
  (the gate population is NEVER narrowed by the entity filter — INV-4 / THREAT-001);
* a clean advisory delta subset is NOT a gate-of-record PASS for skipped files.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from wardline.core.delta_scope import ScopeParseError, parse_affected_scope
from wardline.core.finding import Kind, Severity, SuppressionState
from wardline.core.run import gate_decision, run_scan

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect.
# Mirrors ``_LEAKY`` in test_run.py — the entity ``leaky`` carries the ERROR.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)

# Two CO-LOCATED leaky entities in one module: ``alpha`` and ``beta``. A worklist naming
# only ``alpha`` displays alpha's finding, drops beta's from the displayed set, but keeps
# beta's finding in ``gate_findings`` (the file IS analyzed; the display filter never
# touches the gate population — INV-4 at the Phase 3 seam).
_TWO_ENTITY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef alpha(p):\n    return read_raw(p)\n"
    "@trusted\ndef beta(p):\n    return read_raw(p)\n"
)

_CLEAN = "def touched():\n    return 'safe'\n"


def _two_file_proj(tmp_path: Path) -> Path:
    """A project with two structurally-identical leaky modules, ``good.py`` + ``evil.py``,
    each carrying a PY-WL-101 ERROR on its ``leaky`` entity."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "good.py").write_text(_LEAKY, encoding="utf-8")
    (proj / "evil.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _co_located_proj(tmp_path: Path) -> Path:
    """A project with one module carrying two co-located leaky entities (``alpha``,
    ``beta``)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_TWO_ENTITY, encoding="utf-8")
    return proj


def _clean_plus_skipped_error_proj(tmp_path: Path) -> Path:
    """A project where the affected file is clean but an unanalyzed file has an ERROR."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "good.py").write_text(_CLEAN, encoding="utf-8")
    (proj / "evil.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _py101_paths(findings: list) -> set[str]:
    return {f.location.path for f in findings if f.rule_id == "PY-WL-101"}


def _py101_quals(findings: list) -> set[str]:
    return {f.qualname for f in findings if f.rule_id == "PY-WL-101"}


def test_affected_scopes_analysis_to_subset(tmp_path: Path) -> None:
    """A worklist naming only ``good.leaky`` analyzes ``good.py`` and not ``evil.py``;
    the displayed findings carry only the ``good.py`` PY-WL-101 finding."""
    proj = _two_file_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.leaky"}])

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    assert result.scope.mode == "delta"
    assert result.scope.files_discovered == 2
    assert result.scope.files_analyzed == 1
    # Displayed findings narrowed to the affected entity's file only.
    assert _py101_paths(result.findings) == {"good.py"}


def test_full_path_when_affected_is_none(tmp_path: Path) -> None:
    """``affected is None`` → byte-identical full scan: both files analyzed, both
    PY-WL-101 findings present, and no scope block (INV-1)."""
    proj = _two_file_proj(tmp_path)

    result = run_scan(proj)

    assert result.scope is None
    assert _py101_paths(result.findings) == {"good.py", "evil.py"}


def test_inv1_spy_build_qualname_index_not_called_when_affected_none(tmp_path: Path) -> None:
    """INV-1: the full-scan path pays NO delta cost — ``build_qualname_index`` is never
    invoked when ``affected is None`` (a future refactor cannot make the full path
    silently build the index)."""
    proj = _two_file_proj(tmp_path)

    with patch("wardline.core.run.build_qualname_index") as spy:
        run_scan(proj)

    spy.assert_not_called()


def test_inv1_spy_build_qualname_index_called_in_delta(tmp_path: Path) -> None:
    """The companion: the spy DOES fire when ``affected`` is supplied, so the negative
    assertion above is meaningful (not green because the symbol moved)."""
    proj = _two_file_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.leaky"}])

    # Call through the real implementation while recording the call.
    from wardline.core import delta_resolve

    with patch(
        "wardline.core.run.build_qualname_index",
        wraps=delta_resolve.build_qualname_index,
    ) as spy:
        run_scan(proj, affected=scope)

    spy.assert_called_once()


def test_affected_and_new_since_mutually_exclusive(tmp_path: Path) -> None:
    """``--affected`` and ``--new-since`` scope different things via different mechanisms;
    composing them is rejected loudly with ``ScopeParseError`` (never silently double-
    scoped)."""
    proj = _two_file_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.leaky"}])

    with pytest.raises(ScopeParseError):
        run_scan(proj, affected=scope, new_since="origin/main")


def test_delta_gate_findings_retains_out_of_scope_finding(tmp_path: Path) -> None:
    """INV-4 / THREAT-001: a worklist naming only ``alpha`` narrows the DISPLAYED findings
    (``beta`` dropped) but the gate population (``gate_findings``) STILL contains ``beta``'s
    ERROR — the display filter NEVER narrows the gate, so an attacker-influenceable scope
    cannot forge a green by excluding a co-located sink."""
    proj = _co_located_proj(tmp_path)
    # Names only alpha; beta is the out-of-(display)-scope co-located sink.
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    result = run_scan(proj, affected=scope)

    assert result.scope is not None and result.scope.mode == "delta"
    # Displayed: only alpha. Gate population: BOTH (never narrowed by the filter).
    assert _py101_quals(result.findings) == {"svc.alpha"}
    assert result.gate_findings is not None
    assert _py101_quals(result.gate_findings) == {"svc.alpha", "svc.beta"}
    # The display-excluded beta ERROR is still live in the gate population.
    beta_in_gate = [
        f
        for f in result.gate_findings
        if f.rule_id == "PY-WL-101" and f.qualname == "svc.beta" and f.suppressed is SuppressionState.ACTIVE
    ]
    assert beta_in_gate


def test_delta_gate_verdict_equals_full_scan(tmp_path: Path) -> None:
    """INV-4: the delta gate verdict is IDENTICAL to the full scan's — narrowing the
    DISPLAYED findings to ``alpha`` cannot turn a FAILED into a PASSED, because the gate
    population still carries ``beta``."""
    proj = _co_located_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    full_decision = gate_decision(full, Severity.ERROR)
    delta_decision = gate_decision(delta, Severity.ERROR)

    assert full_decision.tripped is True
    assert delta_decision.tripped == full_decision.tripped
    assert delta_decision.verdict == full_decision.verdict == "FAILED"
    assert delta_decision.exit_class == full_decision.exit_class == 1


def test_delta_gate_decision_is_not_evaluated_for_advisory_subset(tmp_path: Path) -> None:
    """A delta scan that skips files is advisory and cannot certify a severity PASS.

    The analyzed affected file is clean, but the full tree contains an ERROR in a skipped
    file. ``gate_decision(..., ERROR)`` must not report PASSED for the advisory subset; a
    full scan or ``--new-since`` is the gate of record.
    """
    proj = _clean_plus_skipped_error_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.touched"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    full_decision = gate_decision(full, Severity.ERROR)
    delta_decision = gate_decision(delta, Severity.ERROR)

    assert full_decision.verdict == "FAILED"
    assert full_decision.tripped is True
    assert delta.scope is not None
    assert delta.scope.mode == "delta"
    assert delta.scope.gate_authority == "advisory"
    assert delta.scope.files_discovered == 2
    assert delta.scope.files_analyzed == 1
    assert _py101_paths(delta.findings) == set()
    assert delta_decision.verdict == "NOT_EVALUATED"
    assert delta_decision.tripped is False
    assert delta_decision.exit_class == 0
    assert delta_decision.fail_on == "ERROR"
    assert delta_decision.reason is not None and "advisory" in delta_decision.reason


def test_delta_trust_suppressions_gate_population_is_unfiltered(tmp_path: Path) -> None:
    """INV-4 / THREAT-001 under ``--trust-suppressions``: a delta scan MATERIALISES a
    concrete gate population (post-suppression, pre-delta-filter) instead of leaving
    ``gate_findings`` at the ``None`` sentinel — otherwise the gate would fall back to the
    delta-FILTERED ``findings`` and a surgical-exclusion worklist could forge a green.

    The displayed ``findings`` are narrowed to ``alpha``, but the gate population retains
    BOTH co-located ERROR sinks, and the posture still HONORS suppressions (``--trust-
    suppressions`` is unchanged in meaning — only the gate population is now unforgeable)."""
    proj = _co_located_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    result = run_scan(proj, affected=scope, trust_suppressions=True)

    # Displayed: only alpha. Gate population: a CONCRETE list carrying BOTH sinks —
    # never the None sentinel (which would fall back to the filtered display set).
    assert _py101_quals(result.findings) == {"svc.alpha"}
    assert result.gate_findings is not None
    assert _py101_quals(result.gate_findings) == {"svc.alpha", "svc.beta"}
    # The posture is still trust-suppressions (the verdict honors repo suppressions),
    # but it is carried EXPLICITLY, decoupled from the gate_findings sentinel.
    assert result.honors_suppressions is True


def test_delta_trust_suppressions_cannot_forge_green(tmp_path: Path) -> None:
    """INV-4 / THREAT-001: under ``--trust-suppressions`` a surgical-exclusion worklist
    (names only ``alpha``, drops the co-located ``beta`` ERROR from display) MUST NOT turn
    the FULL scan's FAILED verdict into a PASSED. The delta gate verdict is identical to the
    full scan's because the gate evaluates the unfiltered analyzed population."""
    proj = _co_located_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    full = run_scan(proj, trust_suppressions=True)
    delta = run_scan(proj, affected=scope, trust_suppressions=True)

    full_decision = gate_decision(full, Severity.ERROR)
    delta_decision = gate_decision(delta, Severity.ERROR)

    assert full_decision.tripped is True
    assert full_decision.verdict == "FAILED"
    # The surgical exclusion CANNOT produce PASSED — verdict/exit identical to the full scan.
    assert delta_decision.tripped == full_decision.tripped is True
    assert delta_decision.verdict == full_decision.verdict == "FAILED"
    assert delta_decision.exit_class == full_decision.exit_class == 1


def test_empty_scope_falls_back_to_full(tmp_path: Path) -> None:
    """Fail-closed (INV-3): an empty / all-unresolvable scope analyzes EVERYTHING and is
    declared as full-fallback, never a silent narrow."""
    proj = _two_file_proj(tmp_path)
    # All-unresolvable: a locator that matches no entity in the tree.
    scope = parse_affected_scope([{"locator": "python:function:nope.missing"}])

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    assert result.scope.mode == "full-fallback"
    assert result.scope.gate_authority == "gate-of-record"
    assert result.scope.files_analyzed == result.scope.files_discovered == 2
    # Full population displayed in full-fallback.
    assert _py101_paths(result.findings) == {"good.py", "evil.py"}


def test_delta_mode_summary_reflects_filtered_findings(tmp_path: Path) -> None:
    """The summary is derived from the (filtered) emitted findings, so a delta scan's
    active-defect count reflects only the displayed in-scope defects."""
    proj = _two_file_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.leaky"}])

    result = run_scan(proj, affected=scope)

    active_defects = [f for f in result.findings if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE]
    assert result.summary.active == len(active_defects) == 1
