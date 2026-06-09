"""P4 S12 — the safety contract: an un-rekeyed (old-scheme) store makes the next scan
fail LOUD with SCHEME_MISMATCH naming the file + `wardline rekey`, so a missed leg is
impossible to ignore. After the migration, the scan is clean.

No new production code — this consumes P1's load-time scheme assertion end to end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
pytest.importorskip("blake3", reason="run_scan needs wardline[loomweave]")

from click.testing import CliRunner  # noqa: E402

from wardline.cli.main import cli  # noqa: E402
from wardline.core import paths  # noqa: E402

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return raw(p)\n"
)


def test_unrekeyed_store_fails_scheme_mismatch_then_clean_after_rekey(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "svc.py").write_text(_LEAKY, encoding="utf-8")

    # An old-scheme (wlfp1) waivers store left in place by a missed migration leg.
    wp = paths.waivers_path(project)
    wp.parent.mkdir(parents=True, exist_ok=True)
    wp.write_text(
        yaml.safe_dump(
            {"fingerprint_scheme": "wlfp1", "version": 1, "waivers": [{"fingerprint": "a" * 64, "reason": "stale"}]}
        ),
        encoding="utf-8",
    )

    # The next scan must fail LOUD — naming the file and steering to `wardline rekey`.
    before = CliRunner().invoke(cli, ["scan", str(project), "--output", str(tmp_path / "o.jsonl")])
    assert before.exit_code == 2, before.output
    assert "waivers.yaml" in before.output
    assert "wardline rekey" in before.output

    # Migrate, then the same scan is clean (no SCHEME_MISMATCH).
    rk = CliRunner().invoke(cli, ["rekey", str(project)])
    assert rk.exit_code == 0, rk.output

    after = CliRunner().invoke(cli, ["scan", str(project), "--output", str(tmp_path / "o2.jsonl")])
    assert after.exit_code != 2, after.output  # no scheme error (exit 0/1 by gate, never the 2-error)
    assert "does not match this build" not in after.output
