# tests/unit/cli/test_install_pack.py
"""Tests for 'wardline install <pack>' command CLI behavior."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from wardline.cli.main import cli


def test_install_pack_activates_in_yaml(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    # 1. Run install with mock pack
    result = CliRunner().invoke(cli, ["install", "tests.unit.install.mock_pack", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output

    yaml_path = tmp_path / "wardline.yaml"
    assert yaml_path.is_file()

    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert raw == {"packs": ["tests.unit.install.mock_pack"]}
    assert "packs: activated" in result.output

    # 2. Run install with mock pack again (should be idempotent)
    result_second = CliRunner().invoke(cli, ["install", "tests.unit.install.mock_pack", "--root", str(tmp_path)])
    assert result_second.exit_code == 0, result_second.output
    assert "packs: already_active" in result_second.output


def test_install_pack_warns_if_not_importable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    # Run install with a non-existent pack name
    result = CliRunner().invoke(cli, ["install", "non_existent_pack_xyz", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output

    assert "warning: trust-grammar pack 'non_existent_pack_xyz' is not installed or importable locally" in result.output

    # It should still write the pack name to wardline.yaml
    yaml_path = tmp_path / "wardline.yaml"
    assert yaml_path.is_file()
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert raw == {"packs": ["non_existent_pack_xyz"]}
    assert "packs: activated" in result.output
