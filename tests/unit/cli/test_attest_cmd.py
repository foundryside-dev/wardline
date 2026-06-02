# tests/unit/cli/test_attest_cmd.py
"""TDD: `wardline attest` — build / verify a signed evidence bundle.

Thin CLI over ``build_attestation`` / ``verify_attestation``. The harness mints a
project attest key into a throwaway git repo in ``tmp_path`` (the subprocess git
here operates ONLY on that throwaway repo — it is the test harness, not VCS of the
wardline repo) so ``load_attest_key`` finds the ``.env`` key.

Four gates:
1. Build round-trips: a clean repo → exit 0, JSON bundle, signature verifies.
2. No key → exit 2 with a ``wardline install`` hint on stderr.
3. Dirty refused (exit 2, no traceback) but ``--allow-dirty`` works (``dirty: true``).
4. ``--verify`` exit 0 on a valid bundle, exit 1 on a tampered one.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.attest_key import load_attest_key, mint_attest_key

# A decorated module so the engine produces boundaries (mirrors test_assure_cmd.py).
_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "\n"
    "@external_boundary\n"
    "def src():\n"
    "    return _read()\n"
    "\n"
    "def _read():\n"
    "    return object()\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def leak():\n"
    "    return src()\n"
)


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _make_clean_repo(tmp: Path) -> None:
    """Write a decorated module, init a git repo, mint a key, and commit a CLEAN tree.

    Order matters: ``mint_attest_key`` creates ``.env`` (gitignored) AND ``.gitignore``.
    Mint BEFORE ``git add -A`` so ``.gitignore`` is staged and ``.env`` is ignored —
    otherwise an untracked ``.gitignore`` leaves the tree dirty.
    """
    (tmp / "m.py").write_text(_MODULE, encoding="utf-8")
    _git(["init"], tmp)
    _git(["config", "user.email", "test@example.com"], tmp)
    _git(["config", "user.name", "Test"], tmp)
    mint_attest_key(tmp)
    _git(["add", "-A"], tmp)
    _git(["commit", "-m", "init"], tmp)


def test_build_round_trips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean repo attests (exit 0) and the bundle's signature verifies under its key."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    _make_clean_repo(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["attest", str(tmp_path)])
    assert result.exit_code == 0, result.output
    bundle = json.loads(result.output)
    assert bundle["schema"] == "wardline-attest-1"

    key = load_attest_key(tmp_path)
    assert key is not None
    from wardline.core.attest import verify_attestation

    assert verify_attestation(bundle, key)["signature_valid"] is True


def test_no_key_exits_2_with_install_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A tree with no minted key and no env value → exit 2 with a ``wardline install`` hint."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")  # no mint, no .env

    runner = CliRunner()
    result = runner.invoke(cli, ["attest", str(tmp_path)])
    assert result.exit_code == 2
    assert "wardline install" in result.stderr


def test_dirty_refused_but_allow_dirty_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dirty tree is refused cleanly (exit 2, no traceback); ``--allow-dirty`` records ``dirty: true``."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    _make_clean_repo(tmp_path)
    # Make the tree dirty by modifying a tracked file.
    (tmp_path / "m.py").write_text(_MODULE + "\n# touched\n", encoding="utf-8")

    runner = CliRunner()
    refused = runner.invoke(cli, ["attest", str(tmp_path)])
    assert refused.exit_code == 2
    assert "error:" in refused.stderr
    # A clean exit-2, not a crashed traceback.
    assert refused.exception is None or isinstance(refused.exception, SystemExit)

    allowed = runner.invoke(cli, ["attest", str(tmp_path), "--allow-dirty"])
    assert allowed.exit_code == 0, allowed.output
    bundle = json.loads(allowed.output)
    assert bundle["payload"]["dirty"] is True


def test_verify_mode_valid_and_tampered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``--verify`` exits 0 on a valid bundle and 1 on a tampered one; ``--out`` writes the bundle."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    _make_clean_repo(tmp_path)

    runner = CliRunner()
    bundle_path = tmp_path / "attest.json"
    built = runner.invoke(cli, ["attest", str(tmp_path), "--out", str(bundle_path)])
    assert built.exit_code == 0, built.output
    assert bundle_path.is_file()

    ok = runner.invoke(cli, ["attest", str(tmp_path), "--verify", str(bundle_path)])
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.output)["signature_valid"] is True

    # Tamper with a signed payload field and rewrite the bundle.
    tampered = json.loads(bundle_path.read_text(encoding="utf-8"))
    tampered["payload"]["wardline_version"] = "0.0.0-tampered"
    bundle_path.write_text(json.dumps(tampered), encoding="utf-8")

    bad = runner.invoke(cli, ["attest", str(tmp_path), "--verify", str(bundle_path)])
    assert bad.exit_code == 1
    assert json.loads(bad.output)["signature_valid"] is False


def test_verify_malformed_bundle_exits_2_no_traceback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``--verify`` on a file that is not a valid attestation bundle exits 2 with an
    ``error:`` line and NO traceback — consistent with every other CLI error path."""
    monkeypatch.delenv("WARDLINE_ATTEST_KEY", raising=False)
    _make_clean_repo(tmp_path)

    bad_path = tmp_path / "garbage.json"
    bad_path.write_text("not json", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["attest", str(tmp_path), "--verify", str(bad_path)])
    assert result.exit_code == 2
    assert "error:" in result.stderr
    # A clean exit-2, not a crashed traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit)
