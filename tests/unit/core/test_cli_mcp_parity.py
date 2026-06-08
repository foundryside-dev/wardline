"""CLI ↔ MCP finding-parity differential.

"CLI and MCP are identical by construction" is a core tenet (CLAUDE.md): both
surfaces call the same ``core/run.py`` functions, so a scan via the CLI and via
the MCP server must produce the same findings and the same gate decision. That
is asserted by design today but not *guarded* — ``test_mcp_cli.py`` only
exercises the protocol loop, not finding-parity.

This pins it: the same fixture tree, run through the shared default ``run_scan``
path and through the MCP ``_scan`` tool (which also passes ``confine_to_root=True``),
must yield identical findings + gate. If a future MCP-only code path leaks into
the findings, this differential fails.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.agent_summary import build_agent_summary
from wardline.core.finding import Severity
from wardline.core.run import baseline_migration_hint, gate_decision, run_scan
from wardline.mcp.server import _scan

_CORPUS = Path(__file__).resolve().parents[3] / "tests" / "corpus" / "fixtures"


def test_cli_and_mcp_scan_agree_on_findings_and_gate() -> None:
    # Shared scan default: confine_to_root=True. The finding BODIES live solely in
    # agent_summary now (the bloat-causing top-level `findings` array was removed, W1).
    # The CLI `--format agent-summary` is uncapped; MCP defaults bounded, so parity is
    # asserted against MCP full=true (engine parity preserved; only the default page size
    # differs by surface, by design).
    cli_result = run_scan(_CORPUS)
    cli_gate = gate_decision(cli_result, Severity.ERROR)
    cli_ag = build_agent_summary(cli_result, cli_gate).to_dict()

    # MCP parameterization: the real _scan handler (confine_to_root=True, no loomweave).
    mcp = _scan({"fail_on": "ERROR", "full": True}, root=_CORPUS)
    mcp_ag = mcp["agent_summary"]

    for key in ("active_defects", "suppressed_findings", "engine_facts", "informational"):
        assert mcp_ag[key] == cli_ag[key], key
    cli_hint = baseline_migration_hint(cli_result, cli_gate, root=_CORPUS, new_since=None)
    assert mcp["gate"] == {
        "tripped": cli_gate.tripped,
        "fail_on": cli_gate.fail_on,
        "exit_class": cli_gate.exit_class,
        "verdict": cli_gate.verdict,
        "would_trip_at": cli_gate.would_trip_at,
        "reason": cli_gate.reason,
        "evaluated": cli_gate.evaluated,
        "migration_hint": cli_hint,
    }
    assert mcp["summary"]["total"] == cli_result.summary.total
    assert mcp["summary"]["active"] == cli_result.summary.active
    assert mcp["files_scanned"] == cli_result.files_scanned
    # Sanity: the labeled corpus is a non-trivial substrate (it fires real defects).
    assert any(e["kind"] == "defect" for e in cli_ag["active_defects"])


def test_cli_and_mcp_emit_identical_filigree_body() -> None:
    """The Filigree emission set must be identical across surfaces. The CLI passes
    `result.findings` and `result.scanned_paths` to FiligreeEmitter.emit. The MCP
    scan must hand its injected emitter exactly the same finding and scanned-path
    sets, so the POST body is byte-identical."""
    from wardline.core.filigree_emit import EmitResult

    cli_result = run_scan(_CORPUS)

    class _Capture:
        def __init__(self) -> None:
            self.seen: list = []
            self.scanned_paths: tuple[str, ...] = ()

        def emit(self, findings, *, scanned_paths=()):
            self.seen = list(findings)
            self.scanned_paths = tuple(scanned_paths)
            return EmitResult(reachable=True)

    cap = _Capture()
    _scan({}, root=_CORPUS, filigree=cap)

    # The real contract: the MCP scan hands the emitter the SAME unfiltered finding
    # set the CLI passes (result.findings) — guards against a future filter (e.g.
    # active-only) silently diverging the two surfaces' Filigree emission.
    assert [f.fingerprint for f in cap.seen] == [f.fingerprint for f in cli_result.findings]
    assert cap.scanned_paths == cli_result.scanned_paths
