# tests/unit/cli/test_install_pack.py
"""Tests for 'wardline install <pack>' command CLI behavior."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_install_pack_emits_guidance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    result = CliRunner().invoke(cli, ["install", "tests.unit.install.mock_pack", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output

    # Packs are operator-authored in weft.toml; install only emits guidance and
    # writes NO config file.
    assert "weft.toml" in result.output
    assert "tests.unit.install.mock_pack" in result.output
    assert 'packs = ["tests.unit.install.mock_pack"]' in result.output
    assert not (tmp_path / "wardline.yaml").exists()
    assert not (tmp_path / "weft.toml").exists()


def test_install_pack_warns_if_not_importable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    # Run install with a non-existent pack name
    result = CliRunner().invoke(cli, ["install", "non_existent_pack_xyz", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output

    assert "warning: trust-grammar pack 'non_existent_pack_xyz' is not installed or importable locally" in result.output

    # Guidance is still emitted for the (non-importable) pack name; no config is written.
    assert "weft.toml" in result.output
    assert 'packs = ["non_existent_pack_xyz"]' in result.output
    assert not (tmp_path / "wardline.yaml").exists()
    assert not (tmp_path / "weft.toml").exists()
