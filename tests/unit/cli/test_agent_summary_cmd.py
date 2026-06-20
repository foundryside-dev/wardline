from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def raw(p):\n"
    "    return p\n"
    "@trusted\n"
    "def leaky(p):\n"
    "    return raw(p)\n"
)


def test_scan_agent_summary_format_writes_stable_json(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = tmp_path / "summary.json"

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "agent-summary", "--output", str(out)])

    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "wardline-agent-summary-1"
    assert data["active_defects"][0]["rule_id"] == "PY-WL-101"
    assert "summary.json" in result.output


def test_scan_agent_summary_default_output_refuses_repo_symlink(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / ".wardline").symlink_to(outside)

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "agent-summary"])

    assert result.exit_code == 2
    assert "refusing to write through a symlink" in result.stderr
    assert list(outside.iterdir()) == []


def test_scan_agent_summary_default_output_is_timestamped(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "agent-summary"])

    assert result.exit_code == 0, result.output
    paths = sorted((tmp_path / ".wardline").glob("*-findings.agent-summary.json"))
    assert len(paths) == 1
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data["schema"] == "wardline-agent-summary-1"
    assert str(paths[0]) in result.output
