"""CLI ↔ MCP finding-parity differential.

"CLI and MCP are identical by construction" is a core tenet (CLAUDE.md): both
surfaces call the same ``core/run.py`` functions, so a scan via the CLI and via
the MCP server must produce the same findings and the same gate decision. That
is asserted by design today but not *guarded* — ``test_mcp_cli.py`` only
exercises the protocol loop, not finding-parity.

This pins it: the same fixture tree, run the way the CLI invokes ``run_scan``
(``confine_to_root=False``) and the way the MCP ``_scan`` tool invokes it
(``confine_to_root=True``, via the real handler), must yield identical findings
+ gate. The deliberate ``confine_to_root`` difference is a no-op here because the
tree has no source root escaping ``root`` — which is exactly the point: the only
sanctioned divergence doesn't touch results for an in-root scan. If a future
MCP-only code path leaks into the findings, this differential fails.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Severity
from wardline.core.run import gate_decision, run_scan
from wardline.mcp.server import _finding_to_dict, _scan

_CORPUS = Path(__file__).resolve().parents[3] / "tests" / "corpus" / "fixtures"


def test_cli_and_mcp_scan_agree_on_findings_and_gate() -> None:
    # CLI parameterization: confine_to_root defaults to False.
    cli_result = run_scan(_CORPUS)
    cli_findings = [_finding_to_dict(f) for f in cli_result.findings]
    cli_gate = gate_decision(cli_result, Severity.ERROR)

    # MCP parameterization: the real _scan handler (confine_to_root=True, no clarion).
    mcp = _scan({"fail_on": "ERROR"}, root=_CORPUS)

    assert mcp["findings"] == cli_findings
    assert mcp["gate"] == {
        "tripped": cli_gate.tripped,
        "fail_on": cli_gate.fail_on,
        "exit_class": cli_gate.exit_class,
    }
    assert mcp["summary"]["total"] == cli_result.summary.total
    assert mcp["summary"]["active"] == cli_result.summary.active
    assert mcp["files_scanned"] == cli_result.files_scanned
    # Sanity: the labeled corpus is a non-trivial substrate (it fires real defects).
    assert any(f["kind"] == "defect" for f in cli_findings)


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
