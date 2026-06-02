# tests/unit/cli/test_assure_cmd.py
"""TDD: `wardline assure` — thin CLI over ``build_posture``.

Three gates:
1. JSON output equals ``build_posture(...).to_dict()`` for a decorated module.
2. ``--format human`` on the same tree contains the coverage "%" substring.
3. An empty/undecorated tree with ``--format human`` says "nothing to assure"
   and does NOT contain a bare "100% coverage" claim.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.assure import build_posture

# Identical decorated module used by test_assure.py so the engine produces
# boundaries_total >= 1 (two @trusted producers + one @external_boundary = 3).
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

_PLAIN = "def f():\n    return 1\n"


def test_json_output_equals_core(tmp_path: Path) -> None:
    """CLI JSON output must be byte-for-byte identical to ``build_posture(...).to_dict()``."""
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["assure", str(tmp_path)])
    assert result.exit_code == 0, result.output
    cli_dict = json.loads(result.output)
    expected = build_posture(tmp_path).to_dict()
    assert cli_dict == expected


def test_human_format_contains_coverage_pct(tmp_path: Path) -> None:
    """``--format human`` on a decorated tree must contain the coverage percentage."""
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["assure", str(tmp_path), "--format", "human"])
    assert result.exit_code == 0, result.output
    assert "%" in result.output


def test_human_format_empty_surface(tmp_path: Path) -> None:
    """``--format human`` on an undecorated tree must print the empty-surface sentinel
    and must NOT contain a bare "100% coverage" claim."""
    (tmp_path / "m.py").write_text(_PLAIN, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["assure", str(tmp_path), "--format", "human"])
    assert result.exit_code == 0, result.output
    assert "nothing to assure" in result.output.lower()
    # Must not mislead the user with a bare coverage claim on an empty surface.
    assert "100% coverage" not in result.output
