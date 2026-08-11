"""PRD-0003 criterion 1 — the false-green holes, reproduced at the PROCESS EXIT CODE.

Each repro here is a ticket's own scenario re-run end to end through the CLI. The
assertion is deliberately on ``result.exit_code``, not on the presence of a finding:
the ticket's symptom was that ``wardline scan --fail-on ERROR`` exited **0** on code
that should fail, and only an exit-code assertion falsifies that. Every specimen lives
in ``tmp_path`` and in NONE of ``tests/corpus/fixtures`` or
``tests/golden/identity/corpus/*.json``, both of which auto-absorb a stray ``.py`` file
and would convert PRD-0003 criterion 4's guard into a re-freeze.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_hole1_malformed_marker_call_trips_the_gate(tmp_path: Path) -> None:
    # wardline-4928b75782, the ticket's own scenario: an undeclared kwarg on a builtin
    # marker used to drop the seed SILENTLY — the function left declared_qualnames,
    # every tier-modulated rule went quiet, and the gate exited 0 on a real leak.
    # PY-WL-130 is Severity.ERROR, so the gate now trips. The assertion is on the
    # literal PROCESS EXIT CODE, which is what PRD-0003 criterion 1 reads; the mere
    # presence of a finding is a different and weaker claim.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        '@trusted(level="INTEGRAL", audit=True)\ndef leaky(p):\n    return read_raw(p)\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["scan", str(proj), "--fail-on", "ERROR"])
    assert result.exit_code == 1, result.output
