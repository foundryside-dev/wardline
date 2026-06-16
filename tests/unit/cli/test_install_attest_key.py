# tests/unit/cli/test_install_attest_key.py
"""Tests for `wardline install` attest-key minting step."""

from __future__ import annotations

import subprocess
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.attest_key import load_attest_key

# All other install steps are skipped to isolate the attest-key step.
_SKIP_ALL_OTHER = [
    "--no-claude-md",
    "--no-agents-md",
    "--no-skill",
    "--no-mcp",
    "--no-bindings",
]


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_install_mints_attest_key(tmp_path: Path, monkeypatch) -> None:
    """First run: key is minted, .env created, .gitignore contains .env."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), *_SKIP_ALL_OTHER],
    )
    assert result.exit_code == 0, result.output

    # Key is accessible via load_attest_key
    key = load_attest_key(tmp_path)
    assert key is not None

    # .env exists and .gitignore contains .env
    assert (tmp_path / ".env").exists()
    gitignore_text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore_text

    # Output reports status but NOT the key value
    assert "attest key: minted" in result.output
    assert key not in result.output


def test_install_no_attest_key_flag_skips_minting(tmp_path: Path, monkeypatch) -> None:
    """--no-attest-key flag: no key is minted and output has no 'attest key:' line."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), "--no-attest-key", *_SKIP_ALL_OTHER],
    )
    assert result.exit_code == 0, result.output

    assert load_attest_key(tmp_path) is None
    assert "attest key:" not in result.output


def test_install_attest_key_idempotent(tmp_path: Path, monkeypatch) -> None:
    """Second run reports 'present', not 'minted' — idempotent."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    runner = CliRunner()
    args = ["install", "--root", str(tmp_path), *_SKIP_ALL_OTHER]

    first = runner.invoke(cli, args)
    assert first.exit_code == 0, first.output
    assert "attest key: minted" in first.output

    second = runner.invoke(cli, args)
    assert second.exit_code == 0, second.output
    assert "attest key: present" in second.output


def test_install_refuses_to_mint_into_tracked_dotenv(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    _git(["init"], tmp_path)
    _git(["config", "user.email", "test@example.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    dotenv = tmp_path / ".env"
    dotenv.write_text("EXISTING=1\n", encoding="utf-8")
    _git(["add", ".env"], tmp_path)
    _git(["commit", "-m", "track env"], tmp_path)

    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), *_SKIP_ALL_OTHER],
    )

    assert result.exit_code == 2
    assert "tracked .env" in result.stderr
    assert dotenv.read_text(encoding="utf-8") == "EXISTING=1\n"
