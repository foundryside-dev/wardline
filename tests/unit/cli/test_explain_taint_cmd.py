# tests/unit/cli/test_explain_taint_cmd.py
"""N-2 (wardline-0be02bf8e6): `wardline explain-taint` — the CLI twin of the MCP
`explain_taint` tool, so a CLI-only agent does not dead-end at step 2 of the
scan -> explain -> fix -> rescan loop. Thin wrapper over the same core builder
(`core.explain.explain_taint_result`) the MCP handler uses — identical by
construction."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.run import run_scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _leaky_proj(tmp_path: Path) -> tuple[Path, str]:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    fp = next(f for f in run_scan(proj).findings if f.rule_id == "PY-WL-101").fingerprint
    return proj, fp


def test_explain_taint_by_fingerprint(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    res = CliRunner().invoke(cli, ["explain-taint", fp, str(proj)])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["fingerprint"] == fp
    assert payload["rule_id"] == "PY-WL-101"
    assert payload["sink_qualname"] == "svc.leaky"
    assert payload["immediate_tainted_callee"] == "read_raw"
    # the remediation hint rides along, exactly as the MCP result carries it
    assert payload["remediation"]["kind"] == "boundary_placement"


def test_explain_taint_matches_mcp_result_shape(tmp_path: Path) -> None:
    # Identical-by-construction pin: the CLI JSON equals the MCP handler's result
    # dict for the same finding (no chain, no loomweave).
    from wardline.mcp.server import _explain_taint

    proj, fp = _leaky_proj(tmp_path)
    mcp_result = _explain_taint({"fingerprint": fp}, proj)
    res = CliRunner().invoke(cli, ["explain-taint", fp, str(proj)])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output) == mcp_result


def test_explain_taint_stale_fingerprint_exits_2(tmp_path: Path) -> None:
    proj, _ = _leaky_proj(tmp_path)
    res = CliRunner().invoke(cli, ["explain-taint", "0" * 64, str(proj)])
    assert res.exit_code == 2
    err = res.output + res.stderr
    assert "re-scan" in err  # same actionable message the MCP tool returns


def test_explain_taint_listed_in_cli_help() -> None:
    res = CliRunner().invoke(cli, ["--help"])
    assert "explain-taint" in res.output


def test_explain_taint_help_names_the_loop() -> None:
    res = CliRunner().invoke(cli, ["explain-taint", "--help"])
    assert res.exit_code == 0
    assert "fingerprint" in res.output.lower()
