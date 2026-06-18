"""Phase 9 — the five load-bearing invariants of the ``--affected`` delta scan.

These tests pin the security/soundness properties INV-1..INV-5 (plan §Invariants) at
the ``run_scan`` seam, end-to-end, independently of the focused per-phase unit tests:

* **INV-1** — the full-scan path (``affected is None``) is byte-identical to today AND
  pays NO delta cost: ``build_qualname_index`` is never built and an injected loomweave
  SEI resolver is never probed.
* **INV-2** — fingerprints are stable: a finding kept by a delta scan carries the exact
  fingerprint it has in a full scan (the filter drops, never re-mints).
* **INV-3** — fail-closed honesty: an all-unresolvable scope falls back to a FULL scan
  (``mode="full-fallback"``, ``gate_authority="gate-of-record"``) and the finding set
  equals a plain full scan's.
* **INV-4 (THREAT-001, the load-bearing security test)** — an untrusted scope that
  surgically EXCLUDES a real ERROR sink from the DISPLAYED findings while still analyzing
  its file stays ``mode="delta"`` (NOT full-fallback — fail-closed does not catch a
  precise exclusion), narrows the DISPLAYED findings to omit that ERROR, but CANNOT forge
  a green: the severity gate evaluates the unfiltered analyzed population, so the
  verdict/exit are IDENTICAL to the full scan's (FAILED / tripped / exit_class 1).
* **INV-5 (mark_unseen)** — a delta CLI Filigree emit builds the request body with
  ``mark_unseen=False`` so out-of-scope findings (absent from the FILTERED ``findings``
  list but present in the FULL ``scanned_paths``) are never read as fixed and closed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from click.testing import CliRunner

from wardline.cli.scan import scan
from wardline.core.delta_scope import parse_affected_scope
from wardline.core.finding import Severity, SuppressionState
from wardline.core.run import gate_decision, run_scan
from wardline.loomweave.identity import SeiCapability, SeiResolver

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect. The
# entity ``leaky`` carries the ERROR (mirrors ``_LEAKY`` in test_run_affected.py).
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)

# Two CO-LOCATED leaky entities (``alpha``, ``beta``) in one module — used to exercise a
# surgical display-exclusion that the gate must still see (INV-4).
_TWO_ENTITY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef alpha(p):\n    return read_raw(p)\n"
    "@trusted\ndef beta(p):\n    return read_raw(p)\n"
)

# ``evil.py``: a benign affected entity ``touched`` co-located WITH a real ERROR sink
# ``backdoor`` in the SAME file. A worklist naming only ``touched`` makes evil.py the
# analyzed file (so the engine DOES compute the backdoor's ERROR) while surgically
# excluding ``backdoor`` from the DISPLAYED findings — the precise THREAT-001 shape: the
# attacker hides the sink from the report, but it is still in the gate population.
_EVIL = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef touched(p):\n    return 'safe'\n"
    "@trusted\ndef backdoor(p):\n    return read_raw(p)\n"
)


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


def _evil_proj(tmp_path: Path) -> Path:
    """A project whose ``evil.py`` co-locates a benign affected entity ``touched`` with a
    real ERROR sink ``backdoor``, plus a clean ``other.py`` so the scope is a true subset."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "evil.py").write_text(_EVIL, encoding="utf-8")
    (proj / "other.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _py101(findings: list) -> list:
    return [f for f in findings if f.rule_id == "PY-WL-101"]


def _py101_paths(findings: list) -> set[str]:
    return {f.location.path for f in _py101(findings)}


def _py101_quals(findings: list) -> set[str]:
    return {f.qualname for f in _py101(findings)}


def _fp_by_qual(findings: list) -> dict[str, str]:
    return {f.qualname: f.fingerprint for f in _py101(findings)}


def _frozen_finding_repr(findings: list) -> list[tuple]:
    """A stable, order-independent projection of a findings list for byte-identity asserts."""
    return sorted(
        (f.rule_id, f.location.path, f.qualname, f.severity, f.kind, f.suppressed, f.fingerprint) for f in findings
    )


class _SpyClient:
    """A SeiClient double whose every wire call is recorded. INV-1 asserts NONE of these
    fire when ``affected is None`` — the full-scan path probes no loomweave."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def capabilities(self) -> dict[str, Any] | None:
        self.calls.append("capabilities")
        return {"sei": {"supported": True, "version": 1}}

    def resolve_identity(self, locator: str) -> dict[str, Any] | None:
        self.calls.append("resolve_identity")
        return None

    def resolve_sei(self, sei: str) -> dict[str, Any] | None:
        self.calls.append("resolve_sei")
        return None


# --- INV-1 ----------------------------------------------------------------------------


def test_inv1_full_scan_byte_identical_to_no_resolver(tmp_path: Path) -> None:
    """INV-1: a full scan (``affected is None``) yields the same findings, summary,
    gate_findings, and scanned_paths whether or not a resolver is injected — and never a
    scope block. Passing a resolver must not perturb the full-scan path."""
    proj = _two_file_proj(tmp_path)
    spy = _SpyClient()
    resolver = SeiResolver(spy, SeiCapability(supported=True, version=1))

    plain = run_scan(proj)
    with_resolver = run_scan(proj, sei_resolver=resolver)

    assert plain.scope is None and with_resolver.scope is None
    assert _frozen_finding_repr(plain.findings) == _frozen_finding_repr(with_resolver.findings)
    assert plain.summary == with_resolver.summary
    assert plain.scanned_paths == with_resolver.scanned_paths
    assert plain.gate_findings is not None and with_resolver.gate_findings is not None
    assert _frozen_finding_repr(plain.gate_findings) == _frozen_finding_repr(with_resolver.gate_findings)
    # The frozen full-scan expectation: both leaky entities, both files, both gate.
    assert _py101_paths(plain.findings) == {"good.py", "evil.py"}


def test_inv1_no_delta_cost_and_no_loomweave_probe_when_affected_none(tmp_path: Path) -> None:
    """INV-1: the full-scan path pays NO delta cost — ``build_qualname_index`` is never
    invoked — and probes NO loomweave — the injected resolver's client is never touched —
    when ``affected is None`` (a future refactor cannot silently make the full path build
    the index or hit the network)."""
    proj = _two_file_proj(tmp_path)
    spy = _SpyClient()
    resolver = SeiResolver(spy, SeiCapability(supported=True, version=1))

    with patch("wardline.core.run.build_qualname_index") as index_spy:
        run_scan(proj, affected=None, sei_resolver=resolver)

    index_spy.assert_not_called()
    assert spy.calls == []


def test_inv1_negative_control_resolver_probed_in_delta(tmp_path: Path) -> None:
    """The companion control: when ``affected`` IS supplied with an SEI entity, the
    resolver's client IS probed — so the negative assertion above is meaningful (green
    because the path is skipped, not because the resolver is inert)."""
    proj = _two_file_proj(tmp_path)
    spy = _SpyClient()
    resolver = SeiResolver(spy, SeiCapability(supported=True, version=1))
    scope = parse_affected_scope([{"sei": "loomweave:eid:" + "a" * 32}])

    run_scan(proj, affected=scope, sei_resolver=resolver)

    assert "resolve_sei" in spy.calls


# --- INV-2 ----------------------------------------------------------------------------


def test_inv2_kept_finding_fingerprint_matches_full_scan(tmp_path: Path) -> None:
    """INV-2: a finding kept by a delta scan carries the EXACT fingerprint it has in a
    full scan of the same tree — the filter drops findings, it never re-mints identity."""
    proj = _co_located_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    # The delta scan displays only alpha; assert its fingerprint is byte-identical to the
    # same entity's fingerprint in the full scan.
    assert _py101_quals(delta.findings) == {"svc.alpha"}
    full_fps = _fp_by_qual(full.findings)
    delta_fps = _fp_by_qual(delta.findings)
    assert delta_fps["svc.alpha"] == full_fps["svc.alpha"]


def test_inv2_all_kept_fingerprints_stable_across_files(tmp_path: Path) -> None:
    """INV-2 across files: a worklist naming an entity in ``good.py`` keeps that file's
    finding with the same fingerprint a full scan mints for it."""
    proj = _two_file_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:good.leaky"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    full_by_path = {(f.location.path, f.qualname): f.fingerprint for f in _py101(full.findings)}
    for f in _py101(delta.findings):
        assert f.fingerprint == full_by_path[(f.location.path, f.qualname)]


# --- INV-3 ----------------------------------------------------------------------------


def test_inv3_all_unresolvable_falls_back_to_full(tmp_path: Path) -> None:
    """INV-3: an all-unresolvable scope falls back to a FULL scan — ``mode`` is
    ``full-fallback``, ``gate_authority`` is ``gate-of-record``, every file is analyzed,
    and the finding set equals a plain full scan's (never a silent narrow)."""
    proj = _two_file_proj(tmp_path)
    # A locator that matches no entity in the tree → zero files resolve → full-fallback.
    scope = parse_affected_scope([{"locator": "python:function:nope.missing"}])

    full = run_scan(proj)
    fallback = run_scan(proj, affected=scope)

    assert fallback.scope is not None
    assert fallback.scope.mode == "full-fallback"
    assert fallback.scope.gate_authority == "gate-of-record"
    assert fallback.scope.files_analyzed == fallback.scope.files_discovered == 2
    # The finding set is identical to a plain full scan's (full-fallback applies NO filter).
    assert _frozen_finding_repr(fallback.findings) == _frozen_finding_repr(full.findings)


# --- INV-4 (THREAT-001) ----------------------------------------------------------------


def test_inv4_surgical_exclusion_cannot_forge_a_green(tmp_path: Path) -> None:
    """INV-4 / THREAT-001 — the load-bearing security test.

    A worklist that resolves >0 files (so NOT full-fallback) but SURGICALLY EXCLUDES the
    real ERROR sink ``evil.backdoor`` from the DISPLAYED findings — by naming only the
    benign co-located entity ``evil.touched`` — stays ``mode="delta"`` and omits the ERROR
    from the report. evil.py IS still analyzed (the worklist's entity lives there), so the
    engine computes the backdoor's ERROR; the display filter hides it but the severity gate
    evaluates the FULL unsuppressed population, so the verdict/exit are IDENTICAL to a full
    scan's: an attacker-influenceable scope cannot green a real ERROR.

    The complementary inter-file gap (an ERROR in a file the worklist never names, hence
    never analyzed) is the DECLARED soundness limitation surfaced by ``boundary_caveat`` —
    INV-4 protects against the display filter forging a green, not against the honestly-
    declared non-analysis of out-of-scope files.
    """
    proj = _evil_proj(tmp_path)
    # Names only the benign evil.touched: evil.py resolves (>0 files → delta, not
    # full-fallback) AND is analyzed, so backdoor's ERROR is computed but display-excluded.
    scope = parse_affected_scope([{"locator": "python:function:evil.touched"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    # Delta mode (NOT full-fallback): fail-closed-on-empty does NOT catch a precise
    # exclusion, so INV-4 is the structural protection, not a deployment convention.
    assert delta.scope is not None
    assert delta.scope.mode == "delta"
    # The backdoor ERROR is GONE from the displayed findings (surgically excluded by name).
    assert _py101_quals(delta.findings) == set() or "evil.backdoor" not in _py101_quals(delta.findings)
    assert not any(f.location.path == "evil.py" and f.qualname == "evil.backdoor" for f in _py101(delta.findings))
    # ...but it is STILL live in the gate population (the filter never narrows the gate).
    assert delta.gate_findings is not None
    backdoor_in_gate = [
        f
        for f in delta.gate_findings
        if f.rule_id == "PY-WL-101"
        and f.location.path == "evil.py"
        and f.qualname == "evil.backdoor"
        and f.suppressed is SuppressionState.ACTIVE
    ]
    assert backdoor_in_gate, "the surgically-excluded ERROR must remain in the gate population"

    # The gate verdict is IDENTICAL to the full scan's — the delta gate cannot forge a green.
    full_decision = gate_decision(full, Severity.ERROR)
    delta_decision = gate_decision(delta, Severity.ERROR)
    assert full_decision.tripped is True
    assert delta_decision.verdict == full_decision.verdict == "FAILED"
    assert delta_decision.tripped == full_decision.tripped is True
    assert delta_decision.exit_class == full_decision.exit_class == 1


def test_inv4_co_located_surgical_exclusion_cannot_forge_a_green(tmp_path: Path) -> None:
    """INV-4 within a single analyzed file: a worklist naming only ``alpha`` displays just
    alpha's ERROR, but ``beta``'s co-located ERROR stays in the gate population, so the
    delta gate verdict still equals the full scan's FAILED."""
    proj = _co_located_proj(tmp_path)
    scope = parse_affected_scope([{"locator": "python:function:svc.alpha"}])

    full = run_scan(proj)
    delta = run_scan(proj, affected=scope)

    assert delta.scope is not None and delta.scope.mode == "delta"
    assert _py101_quals(delta.findings) == {"svc.alpha"}
    assert delta.gate_findings is not None
    assert _py101_quals(delta.gate_findings) == {"svc.alpha", "svc.beta"}

    assert gate_decision(full, Severity.ERROR).verdict == "FAILED"
    assert gate_decision(delta, Severity.ERROR).verdict == "FAILED"
    assert gate_decision(delta, Severity.ERROR).exit_class == 1


def test_inv4_surgical_exclusion_cannot_forge_a_green_under_trust_suppressions(tmp_path: Path) -> None:
    """INV-4 / THREAT-001 under ``--trust-suppressions`` — the dangerous combination.

    With ``trust_suppressions=True`` the gate would, on a FULL scan, fall back to the
    suppressed ``findings`` (``gate_findings is None``). A delta scan filters ``findings``,
    so a naive fallback would let a surgical-exclusion worklist hide an in-analyzed-file
    ERROR from the gate and forge a PASSED. The fix MATERIALISES a concrete gate population
    (post-suppression, pre-delta-filter), so the delta gate verdict is IDENTICAL to the
    full scan's FAILED even though the ERROR was excluded from the DISPLAYED set."""
    proj = _evil_proj(tmp_path)
    # Names only the benign evil.touched; evil.py is analyzed (backdoor's ERROR is computed)
    # but the worklist surgically drops backdoor from the displayed findings.
    scope = parse_affected_scope([{"locator": "python:function:evil.touched"}])

    full = run_scan(proj, trust_suppressions=True)
    delta = run_scan(proj, affected=scope, trust_suppressions=True)

    # Delta mode (NOT full-fallback) — a precise exclusion does not trip fail-closed.
    assert delta.scope is not None and delta.scope.mode == "delta"
    # The backdoor ERROR is surgically excluded from the DISPLAYED findings...
    assert not any(f.location.path == "evil.py" and f.qualname == "evil.backdoor" for f in _py101(delta.findings))
    # ...but the gate population is a CONCRETE list (the None sentinel was materialised) that
    # still carries the backdoor ERROR; the posture stays trust-suppressions.
    assert delta.gate_findings is not None
    assert delta.honors_suppressions is True
    assert any(f.location.path == "evil.py" and f.qualname == "evil.backdoor" for f in _py101(delta.gate_findings))

    # The surgical exclusion CANNOT forge a green: verdict/exit identical to the full scan's.
    full_decision = gate_decision(full, Severity.ERROR)
    delta_decision = gate_decision(delta, Severity.ERROR)
    assert full_decision.tripped is True
    assert full_decision.verdict == "FAILED"
    assert delta_decision.verdict == full_decision.verdict == "FAILED"
    assert delta_decision.tripped == full_decision.tripped is True
    assert delta_decision.exit_class == full_decision.exit_class == 1


# --- INV-5 (mark_unseen) --------------------------------------------------------------


class _RecordingTransport:
    """A Filigree transport double that captures every POST body, so INV-5 can assert the
    request body's ``mark_unseen`` flag at the WIRE (the body builder), not just the
    emitter argument."""

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def post(self, url: str, body: bytes, headers: Any):  # type: ignore[no-untyped-def]
        from wardline.core.filigree_emit import Response

        self.bodies.append(json.loads(body.decode("utf-8")))
        return Response(status=200, body=json.dumps({"stats": {}}))


def _worklist_file(tmp_path: Path, locator: str) -> Path:
    """A minimal warpline.reverify_worklist.v1 envelope file naming ``locator``."""
    path = tmp_path / "worklist.json"
    path.write_text(
        json.dumps({"data": {"items": [{"entity": {"locator": locator}}]}}),
        encoding="utf-8",
    )
    return path


def test_inv5_delta_emit_body_forces_mark_unseen_false(tmp_path: Path, monkeypatch) -> None:
    """INV-5: a delta CLI Filigree emit builds the request BODY with ``mark_unseen=False``.

    A delta scan emits the FULL discovery list as ``scanned_paths`` but a FILTERED
    ``findings`` list; if Filigree's absent-fingerprint sweep ran, every out-of-scope
    finding would be read as fixed and its issue closed (irreversible signal loss). We
    capture the actual wire body via a recording transport — proving the whole chain
    (CLI → FiligreeEmitter → _scan_result_chunks(force_no_mark_unseen) → body builder)
    yields ``mark_unseen: false`` — not merely that the CLI passes the right argument.
    """
    transport = _RecordingTransport()

    def _emitter_factory(url: str, **kwargs: Any):  # type: ignore[no-untyped-def]
        from wardline.core.filigree_emit import FiligreeEmitter

        kwargs.pop("transport", None)
        return FiligreeEmitter(url, transport=transport, **kwargs)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _emitter_factory)
    monkeypatch.setattr("wardline.filigree.config.load_filigree_token", lambda root: None)

    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")
    out = proj / "findings.jsonl"

    result = CliRunner().invoke(
        scan,
        [
            str(proj),
            "--affected",
            str(worklist),
            "--filigree-url",
            "http://example.invalid/api/scan-results",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert transport.bodies, "the delta emit must have POSTed at least one chunk"
    # The wire body — every chunk — disables reconciliation in delta mode.
    assert all(body["mark_unseen"] is False for body in transport.bodies)
    # The body names the FULL discovery (both files) as scanned_paths while findings are
    # the filtered subset — the exact shape mark_unseen would mis-reconcile.
    scanned = set()
    for body in transport.bodies:
        scanned.update(body.get("scanned_paths", []))
    assert {"good.py", "evil.py"} <= scanned


def test_inv5_full_scan_emit_body_allows_auto_mark_unseen(tmp_path: Path, monkeypatch) -> None:
    """The companion: a FULL scan emit body carries ``mark_unseen=True`` (auto-enabled when
    findings/scanned_paths are non-empty), so reconciliation proceeds normally — the INV-5
    guard is specific to delta mode and does not over-disable reconciliation."""
    transport = _RecordingTransport()

    def _emitter_factory(url: str, **kwargs: Any):  # type: ignore[no-untyped-def]
        from wardline.core.filigree_emit import FiligreeEmitter

        kwargs.pop("transport", None)
        return FiligreeEmitter(url, transport=transport, **kwargs)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _emitter_factory)
    monkeypatch.setattr("wardline.filigree.config.load_filigree_token", lambda root: None)

    proj = _two_file_proj(tmp_path)
    out = proj / "findings.jsonl"

    result = CliRunner().invoke(
        scan,
        [
            str(proj),
            "--filigree-url",
            "http://example.invalid/api/scan-results",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert transport.bodies
    # A full scan has findings + scanned_paths, so the auto-sweep is on (mark_unseen=True).
    assert any(body["mark_unseen"] is True for body in transport.bodies)
