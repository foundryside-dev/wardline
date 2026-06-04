"""Dogfood the assure/attest loop on a committed annotated trust surface."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

_KEY = "1" * 64
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "dogfood_trust_surface"


def test_dogfood_assure_and_attest_verify_reproduce(tmp_path: Path, monkeypatch) -> None:
    """CI exercises a non-vacuous trust surface without annotating Wardline production code."""
    project = tmp_path / "dogfood"
    shutil.copytree(_FIXTURE, project)
    monkeypatch.setenv("WARDLINE_ATTEST_KEY", _KEY)
    runner = CliRunner()

    assured = runner.invoke(cli, ["assure", str(project)])
    assert assured.exit_code == 0, assured.output
    posture = json.loads(assured.output)
    assert posture["boundaries_total"] > 0
    assert posture["coverage_pct"] is not None

    bundle_path = tmp_path / "attest.json"
    attested = runner.invoke(cli, ["attest", str(project), "--out", str(bundle_path)])
    assert attested.exit_code == 0, attested.output
    bundle = json.loads(attested.output)
    assert bundle["payload"]["boundaries"]

    verified = runner.invoke(cli, ["attest", str(project), "--verify", str(bundle_path), "--reproduce"])
    assert verified.exit_code == 0, verified.output
    result = json.loads(verified.output)
    assert result["signature_valid"] is True
    assert result["reproduced"] is True
