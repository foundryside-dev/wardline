"""Warpline delta-scope conformance golden (hermetic, every PR, no sibling).

This is the always-on contract guard for ``wardline scan --affected`` (spec §8). It
pins the delta-scope behavior against a FIXED ``warpline.reverify_worklist.v1`` fixture
and a small sample tree, **importing nothing from a warpline package** — the worklist
shape is vendored faithfully from spec §9, exactly as ``test_legis_intake_contract.py``
vendors the legis ingest contract and ``test_sei_oracle.py`` vendors the loomweave SEI
oracle. Warpline is the fixed external producer; wardline is the consumer of the scope
set. There is no live sibling here (the SEI path is covered by the Phase 2 unit double
and the Phase 11 ``warpline_e2e`` live oracle); these goldens run on every PR with no
network and no binary.

The sample tree (``fixtures/warpline_delta/sample_tree/``):

* ``a.py`` — the affected module: ``alpha`` (named by the worklist) and ``gamma`` (a
  CO-LOCATED entity NOT named) each carry a PY-WL-101 ERROR.
* ``b.py`` — an unaffected module whose ``beta`` carries its own PY-WL-101 ERROR; no
  worklist names it, so ``b.py`` is never analyzed in delta mode.
* ``source_mod.py`` / ``sink_mod.py`` — a CROSS-FILE taint flow: the ``@external_boundary``
  source lives in ``source_mod`` (the changed callee the worklist names), and the
  PY-WL-101 finding anchors caller-side in ``sink_mod.downstream_sink``. Proves the
  reverse-edge caller closure (spec §5.3a) pulls the caller file in.

The seven axes asserted below mirror the plan's Phase 6 list (the spec's three golden
axes — scoped file set, filtered finding set, scope block — plus fallback, the
unresolved-entity path, the load-bearing caller-closure / inter-file taint axis with a
negative case, and the gate-not-narrowed axis that re-states INV-4 at the golden level).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from wardline.core.delta_resolve import build_qualname_index, resolve_affected_scope
from wardline.core.delta_scope import BOUNDARY_CAVEAT, parse_affected_scope
from wardline.core.finding import Severity
from wardline.core.run import gate_decision, run_scan

_FIXTURES = Path(__file__).parent / "fixtures" / "warpline_delta"
_SAMPLE_TREE = _FIXTURES / "sample_tree"


def _load_worklist(name: str) -> object:
    """Read a vendored ``warpline.reverify_worklist.v1`` fixture as decoded JSON.

    The fixture shape is the faithful spec §9 envelope (``{schema, data: {items:
    [{entity:{locator, sei}, priority, reason, depth, why, suggested_verification,
    enrichment}]}}``); only ``items[].entity.{locator, sei}`` is load-bearing for the
    parser, and the rich surrounding fields prove it tolerates the real producer shape."""
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _project(tmp_path: Path) -> Path:
    """Copy the sample tree into a writable scan root (the convention other conformance
    goldens follow — never scan the fixtures dir in place)."""
    proj = tmp_path / "proj"
    shutil.copytree(_SAMPLE_TREE, proj)
    return proj


def _py101(findings: object) -> set[tuple[str | None, str]]:
    assert isinstance(findings, list)
    return {(f.qualname, f.location.path) for f in findings if f.rule_id == "PY-WL-101"}


# --- Axis 1: scoped file set ------------------------------------------------------


def test_axis1_scoped_file_set(tmp_path: Path) -> None:
    """A worklist naming ``a.alpha`` analyzes ONLY ``a.py``; ``b.py``'s ``beta`` finding
    is absent because ``b.py`` never reaches the analyzer (spec §5.3)."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_alpha.v1.json"))

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    assert result.scope.mode == "delta"
    assert result.scope.files_analyzed == 1
    assert result.scope.files_discovered == 4
    # b.py's beta finding is absent from the displayed set (b.py was not analyzed).
    displayed = _py101(result.findings)
    assert ("b.beta", "b.py") not in displayed
    assert all(path == "a.py" for _, path in displayed)


# --- Axis 2: filtered finding set -------------------------------------------------


def test_axis2_filtered_finding_set(tmp_path: Path) -> None:
    """The affected entity ``alpha``'s finding is displayed; the CO-LOCATED non-affected
    ``gamma`` finding (same analyzed file) is filtered out of the display (spec §5.3)."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_alpha.v1.json"))

    result = run_scan(proj, affected=scope)

    displayed = _py101(result.findings)
    assert ("a.alpha", "a.py") in displayed
    assert ("a.gamma", "a.py") not in displayed


# --- Axis 3: the scope block ------------------------------------------------------


def test_axis3_scope_block(tmp_path: Path) -> None:
    """The ``scope`` honesty block carries delta mode, the requested-entity count, the
    analyzed-file count, the in-scope finding count, and the EXACT boundary caveat."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_alpha.v1.json"))

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    block = result.scope
    assert block.mode == "delta"
    assert block.gate_authority == "advisory"
    assert block.entities_requested == 1
    assert block.files_analyzed == 1
    assert block.in_scope_findings == 1
    assert block.boundary_caveat == BOUNDARY_CAVEAT
    # The caveat names the in-scope-correctness hazard, not just out-of-scope omission.
    assert "can read clean without being clean" in block.boundary_caveat


# --- Axis 4: fail-closed full-fallback --------------------------------------------


def test_axis4_full_fallback_when_all_unresolvable(tmp_path: Path) -> None:
    """An all-unresolvable worklist falls back to a FULL scan (fail-closed, INV-3): mode
    ``full-fallback``, ``gate-of-record`` authority, every file analyzed, full display."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_all_unresolvable.v1.json"))

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    assert result.scope.mode == "full-fallback"
    assert result.scope.gate_authority == "gate-of-record"
    assert result.scope.files_analyzed == result.scope.files_discovered == 4
    # The full population is displayed in full-fallback (no silent narrow).
    displayed = _py101(result.findings)
    assert ("a.alpha", "a.py") in displayed
    assert ("a.gamma", "a.py") in displayed
    assert ("b.beta", "b.py") in displayed


# --- Axis 5: the unresolved-entity path -------------------------------------------


def test_axis5_partial_resolution_lists_unresolved(tmp_path: Path) -> None:
    """A worklist with one resolvable (``a.alpha``) + one bogus entity stays in DELTA mode
    (not fallback — >0 files resolved), lists the bogus entity in ``unresolved_entities``,
    and scopes the analysis to the resolved subset (spec §7)."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_partial.v1.json"))

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    block = result.scope
    assert block.mode == "delta"  # NOT full-fallback — a.alpha resolved
    assert block.files_analyzed == 1
    assert block.entities_requested == 2
    unresolved_locators = {e.get("locator") for e in block.unresolved_entities}
    assert "python:function:ghost.module.nowhere" in unresolved_locators
    assert "python:function:a.alpha" not in unresolved_locators
    # The resolvable entity's finding is displayed.
    assert ("a.alpha", "a.py") in _py101(result.findings)


# --- Axis 6: caller-closure / inter-file taint (load-bearing, spec §5.3a) ----------


def test_axis6_caller_closure_computes_inter_file_sink(tmp_path: Path) -> None:
    """A worklist naming the changed CALLEE/source (``source_mod.tainted_source``) pulls
    the caller file ``sink_mod.py`` into the analyzed set via the reverse-edge closure, so
    the cross-file taint finding (which anchors caller-side in ``sink_mod.downstream_sink``)
    IS computed. This pins the inter-file gap as covered, not latent."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_caller_closure.v1.json"))

    result = run_scan(proj, affected=scope)

    assert result.scope is not None
    assert result.scope.mode == "delta"
    # Closure expanded the analyzed set from {source_mod.py} to include sink_mod.py.
    assert result.scope.files_analyzed == 2
    # The caller-side sink finding was computed (present in the gate population — it is not
    # in the DISPLAY because the base affected entity is the source, not the sink; INV-4).
    assert result.gate_findings is not None
    assert any(f.qualname == "sink_mod.downstream_sink" and f.rule_id == "PY-WL-101" for f in result.gate_findings)


def test_axis6_negative_without_closure_the_finding_is_missing(tmp_path: Path) -> None:
    """The negative case proving the closure is what saves it: the resolution layer's BASE
    file set for the source-naming worklist is ``{source_mod.py}`` (the closure adds
    ``sink_mod.py``), and scanning ``source_mod.py`` ALONE — i.e. with no caller in the
    analyzed set, the closure-disabled outcome — computes NO ``downstream_sink`` finding."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_caller_closure.v1.json"))

    # The closure is the only reason sink_mod.py enters the analyzed set: the BASE affected
    # qualname set is just the source, and the source's own file is the only base file.
    files = sorted(proj.glob("*.py"))
    index = build_qualname_index(files, proj)
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.affected_qualnames == frozenset({"source_mod.tainted_source"})
    assert resolved.files == frozenset({"source_mod.py", "sink_mod.py"})

    # With the caller file absent (closure disabled), the sink finding does not exist at
    # all: scan a tree containing ONLY the source module.
    source_only = tmp_path / "source_only"
    source_only.mkdir()
    shutil.copy(proj / "source_mod.py", source_only / "source_mod.py")
    bare = run_scan(source_only)
    assert not any(f.qualname == "sink_mod.downstream_sink" for f in bare.findings)
    assert not any(f.rule_id == "PY-WL-101" for f in bare.findings)


# --- Axis 7: gate-not-narrowed (INV-4 / THREAT-001 at the golden level) ------------


def test_axis7_gate_population_not_narrowed(tmp_path: Path) -> None:
    """The CO-LOCATED non-affected ``gamma`` finding is ABSENT from the displayed findings
    but PRESENT in ``gate_findings`` — the display filter narrows only the display, never
    the gate population, so an attacker-influenceable scope cannot forge a green (INV-4).
    The delta gate verdict is IDENTICAL to the full scan's over the same population."""
    proj = _project(tmp_path)
    scope = parse_affected_scope(_load_worklist("worklist_alpha.v1.json"))

    delta = run_scan(proj, affected=scope)

    # gamma dropped from the DISPLAY but live in the GATE population.
    assert ("a.gamma", "a.py") not in _py101(delta.findings)
    assert delta.gate_findings is not None
    assert ("a.gamma", "a.py") in _py101(delta.gate_findings)

    # The delta gate cannot green a real ERROR: its verdict matches a full scan's gate over
    # the same (a.py) population. (b.py is not analyzed in delta; the gate axis here is the
    # co-located gamma the DISPLAY excluded yet the gate retains.)
    delta_decision = gate_decision(delta, Severity.ERROR)
    assert delta_decision.tripped is True
    assert delta_decision.verdict == "FAILED"
    assert delta_decision.exit_class == 1
