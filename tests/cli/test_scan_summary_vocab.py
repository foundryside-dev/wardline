"""Discipline tests pinning the finding-lifecycle vocabulary across surfaces.

The canonical term for a non-suppressed DEFECT in the emitted findings is
"active" — used by the ``SuppressionState.ACTIVE`` enum, the ``ScanSummary.active``
field, the MCP scan-response ``summary.active`` key, the agent-summary
``active_defects`` key, and the ``wardline:loop`` prompt. These tests pin the CLI
human summary line to the same word so an agent never has to reconcile a CLI
"N new" against an MCP "active".

See ``docs/reference/finding-lifecycle-vocabulary.md``.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.agent_summary import build_agent_summary
from wardline.core.run import gate_decision, run_scan

_ONE_ACTIVE_DEFECT = """from wardline.decorators import trust_boundary, external_boundary

@external_boundary
def read_raw(p):
    return p

@trust_boundary(to_level='ASSURED')
def v(p):
    return read_raw(p)
"""


def _write_fixture(tmp_path: Path) -> Path:
    (tmp_path / "m.py").write_text(_ONE_ACTIVE_DEFECT, encoding="utf-8")
    return tmp_path


def test_scan_summary_uses_active_not_new(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    res = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0, res.output
    out = res.output
    # The non-suppressed count is labelled "active", never "new".
    assert re.search(r"\d+ active", out), out
    assert not re.search(r"\d+ new\b", out), out


def test_active_term_consistent_across_surfaces(tmp_path: Path) -> None:
    _write_fixture(tmp_path)

    result = run_scan(tmp_path)
    decision = gate_decision(result, None)
    n_active = result.summary.active
    assert n_active == 1

    # agent-summary: ``active_defects`` (descriptive-suffix convention) equals the count.
    agent = build_agent_summary(result, decision).to_dict()
    assert agent["summary"]["active_defects"] == n_active

    # MCP scan response: the summary key is "active" (and never "new").
    from wardline.mcp import server

    mcp_summary = server._scan({"path": "."}, tmp_path)["summary"]
    assert mcp_summary["active"] == n_active
    assert "new" not in mcp_summary

    # CLI human line: the count printed for "active" matches.
    res = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 0, res.output
    m = re.search(r"(\d+) active", res.output)
    assert m is not None, res.output
    assert int(m.group(1)) == n_active
