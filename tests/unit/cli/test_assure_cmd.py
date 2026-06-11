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

from wardline.cli.assure import _render_human
from wardline.cli.main import cli
from wardline.core.assure import AssurancePosture, UnknownBoundary, build_posture

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
_BAD_DECORATED = (
    "from wardline.decorators.trust import trusted\n\n@trusted(level='INTEGRAL')\ndef broken(:\n    return 1\n"
)


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


def test_human_format_unanalyzed_files_are_not_full_coverage(tmp_path: Path) -> None:
    (tmp_path / "good.py").write_text(_MODULE, encoding="utf-8")
    (tmp_path / "bad.py").write_text(_BAD_DECORATED, encoding="utf-8")

    result = CliRunner().invoke(cli, ["assure", str(tmp_path), "--format", "human"])

    assert result.exit_code == 0, result.output
    assert "100.0%" not in result.output
    assert "75.0%" in result.output
    assert "unanalyzed files: 1" in result.output


def test_human_format_escapes_repository_control_chars(capsys) -> None:
    posture = AssurancePosture(
        boundaries_total=1,
        proven=0,
        defect_total=0,
        unknown=[
            UnknownBoundary(
                qualname="svc.\x1b]52;clipboard",
                tier="ASSURED",
                path="evil\nname.py",
                line=7,
                reason="\x1b[31mrecursion",
            )
        ],
        engine_limited=1,
        coverage_pct=0.0,
        unanalyzed_total=0,
        unanalyzed_rule_ids=[],
        waiver_debt=[],
        baselined_total=0,
        judged_total=0,
    )

    _render_human(posture)
    out = capsys.readouterr().out

    assert "\x1b" not in out
    assert "evil\nname.py" not in out
    assert r"svc.\x1b]52;clipboard" in out
    assert r"evil\nname.py" in out
    assert r"\x1b[31mrecursion" in out


def test_human_lapsed_waiver_wording(tmp_path: Path) -> None:
    """A lapsed waiver must say "expired N day(s) ago", not "-N day(s) until earliest expiry"."""
    # Write a decorated module so the posture is non-empty, then invoke via JSON
    # to inspect waiver_debt directly, and human to check the wording.
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    # Waiver with an expiry in the past (2026-01-01 is well before today 2026-06-03).
    # Waivers are now project-root state under .weft/wardline/waivers.yaml, not config.
    from datetime import date

    from wardline.core.paths import waivers_path
    from wardline.core.waivers import add_waiver

    add_waiver(
        waivers_path(tmp_path),
        fingerprint="a" * 64,
        reason="old",
        expires=date(2026, 1, 1),
        root=tmp_path,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["assure", str(tmp_path), "--format", "human"])
    assert result.exit_code == 0, result.output
    # Must say "expired N day(s) ago", not a negative "until expiry".
    assert "expired" in result.output.lower()
    assert "ago" in result.output.lower()
    # The negative "until" wording must be gone.
    assert "until earliest expiry" not in result.output or "-" not in result.output
