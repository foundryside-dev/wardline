from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

_SRC = "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n"
_UNKNOWN_SRC = "import weft_markers\n@weft_markers.audit_record\ndef f(): ...\n"
_UNREADABLE_SRC = (
    "from wardline.decorators import trusted\n"
    "def get_level():\n"
    "    return 'ASSURED'\n"
    "DYN = get_level()\n"
    "@trusted(level=DYN)\n"
    "def g(p):\n"
    "    return p\n"
)


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


def test_decorator_coverage_cli_human_shows_both_marker_counts(tmp_path: Path) -> None:
    # The human renderer must carry BOTH side-channel counts, not just the schema.
    (tmp_path / "unknown_marker.py").write_text(_UNKNOWN_SRC, encoding="utf-8")
    (tmp_path / "unreadable_value.py").write_text(_UNREADABLE_SRC, encoding="utf-8")

    result = CliRunner().invoke(cli, ["decorator-coverage", str(tmp_path), "--format", "human"])

    assert result.exit_code == 0, result.output
    assert "unknown_markers=1" in result.output
    assert "unreadable_marker_values=1" in result.output
