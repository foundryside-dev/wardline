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
        "fail_on_unanalyzed": cli_gate.fail_on_unanalyzed,
        "exit_class": cli_gate.exit_class,
        "verdict": cli_gate.verdict,
        "severity_tripped": cli_gate.severity_tripped,
        "unanalyzed_tripped": cli_gate.unanalyzed_tripped,
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


def test_cli_and_mcp_scan_agree_on_rust_findings(tmp_path: Path) -> None:
    """A1 (wardline-2ee1bbda82): the Rust frontend must yield the SAME findings over
    both surfaces. The CLI side is the REAL Click command (`scan --lang rust`) writing
    jsonl; the MCP side is `_scan({"lang": "rust", ...})`. Every agent_summary bucket
    entry carries a fingerprint, so the union must equal the CLI's emitted finding set,
    and the gate verdicts must agree."""
    import json

    import pytest

    pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")
    from click.testing import CliRunner

    from wardline.cli.scan import scan as scan_cmd

    trusted = "/// @trusted(level=ASSURED)\n"
    (tmp_path / "hot.rs").write_text(
        trusted + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "clean.rs").write_text(trusted + 'fn ok() {\n    Command::new("ls").output();\n}\n', encoding="utf-8")

    out = tmp_path / "findings.jsonl"
    cli = CliRunner().invoke(scan_cmd, [str(tmp_path), "--lang", "rust", "--fail-on", "ERROR", "--output", str(out)])
    assert cli.exit_code == 1  # the RS-WL-108 injection trips the gate
    cli_fps = sorted(json.loads(line)["fingerprint"] for line in out.read_text().splitlines() if line.strip())

    mcp = _scan({"lang": "rust", "fail_on": "ERROR", "full": True}, root=tmp_path)
    ag = mcp["agent_summary"]
    mcp_fps = sorted(
        e["fingerprint"]
        for key in ("active_defects", "suppressed_findings", "engine_facts", "informational")
        for e in ag[key]
    )
    assert mcp_fps == cli_fps
    assert mcp["gate"]["tripped"] is True
    assert mcp["gate"]["verdict"] == "FAILED"
    # Engine-level parity too: the shared run_scan path under lang="rust" is what both drove.
    engine = run_scan(tmp_path, lang="rust")
    assert sorted(f.fingerprint for f in engine.findings) == cli_fps


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


def test_cli_and_mcp_agree_on_fail_on_unanalyzed_gate(tmp_path: Path) -> None:
    """A4 (wardline-7fd0f3a82c): the unanalyzed gate must be controllable over BOTH
    surfaces and yield the SAME verdict. The CLI side is the REAL Click command; the MCP
    side is `_scan` with the new `fail_on_unanalyzed` arg. Fixture: an unparseable file
    (discovered but never analysed) and no severity threshold."""
    from click.testing import CliRunner

    from wardline.cli.scan import scan as scan_cmd

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "bad.py").write_text("def f(:\n", encoding="utf-8")  # syntax error -> unanalyzed

    for knob, expect_trip in ((True, True), (False, False)):
        cli_args = [str(proj), "--output", str(tmp_path / "f.jsonl")]
        cli_args.append("--fail-on-unanalyzed" if knob else "--no-fail-on-unanalyzed")
        cli = CliRunner().invoke(scan_cmd, cli_args)
        mcp = _scan({"fail_on_unanalyzed": knob}, root=proj)
        assert cli.exit_code == (1 if expect_trip else 0), cli.output
        assert mcp["gate"]["tripped"] is expect_trip
        assert mcp["gate"]["exit_class"] == cli.exit_code
        assert mcp["gate"]["fail_on_unanalyzed"] is knob
        assert mcp["gate"]["unanalyzed_tripped"] is expect_trip
        assert mcp["summary"]["unanalyzed"] >= 1
        if expect_trip:
            assert mcp["gate"]["verdict"] == "FAILED"
            assert "not analyzed" in (mcp["gate"]["reason"] or "")
        else:
            # Knob off + no threshold: the gate never ran — released behaviour.
            assert mcp["gate"]["verdict"] == "NOT_EVALUATED"
