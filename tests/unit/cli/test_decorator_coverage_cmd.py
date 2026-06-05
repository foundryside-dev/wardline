from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

_SRC = "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n"


def test_decorator_coverage_cli_json(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")

    result = CliRunner().invoke(cli, ["decorator-coverage", str(tmp_path)])

    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert out["summary"]["total"] == 1
    assert out["rows"][0]["qualname"] == "svc.f"


def test_decorator_coverage_cli_human(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")

    result = CliRunner().invoke(cli, ["decorator-coverage", str(tmp_path), "--format", "human"])

    assert result.exit_code == 0, result.output
    assert "svc.f" in result.output
    assert "clean" in result.output
