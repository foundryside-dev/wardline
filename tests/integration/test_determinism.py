"""Determinism tests — scanner produces byte-identical output on repeated runs."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path


def _extract_sarif(output: str) -> str:
    """Extract JSON block from mixed CliRunner output."""
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        return ""
    return output[start : end + 1]


def _run_scan(path: str, manifest: str) -> str:
    """Run wardline scan and return the SARIF JSON string."""
    from wardline.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan", path,
            "--manifest", manifest,
            "--verification-mode",
            "--allow-registry-mismatch",
        ],
    )
    return _extract_sarif(result.stdout)


@pytest.mark.integration
class TestDeterminism:
    """Scanner produces identical output on repeated runs."""

    def test_single_file_deterministic(self, tmp_path: Path) -> None:
        """Scanning a single file twice produces identical SARIF."""
        py_file = tmp_path / "module.py"
        py_file.write_text(textwrap.dedent("""\
            def process(data):
                x = data.get("key", "default")
                y = getattr(data, "attr", None)
        """))

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(textwrap.dedent("""\
            tiers:
              - id: "EXTERNAL_RAW"
                tier: 4
            module_tiers:
              - path: "module.py"
                default_taint: "EXTERNAL_RAW"
            metadata:
              organisation: "test"
        """))

        run1 = _run_scan(str(tmp_path), str(manifest))
        run2 = _run_scan(str(tmp_path), str(manifest))

        assert run1 == run2, "SARIF output differs between runs"
        assert len(run1) > 100, "SARIF output suspiciously short"

    def test_multi_file_deterministic(self, tmp_path: Path) -> None:
        """Scanning multiple files produces identical SARIF."""
        for name in ["alpha.py", "beta.py", "gamma.py"]:
            py_file = tmp_path / name
            py_file.write_text(textwrap.dedent(f"""\
                def handle_{name.replace('.py', '')}(data):
                    x = data.get("key", "default")
            """))

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(textwrap.dedent("""\
            tiers:
              - id: "EXTERNAL_RAW"
                tier: 4
            module_tiers:
              - path: "."
                default_taint: "EXTERNAL_RAW"
            metadata:
              organisation: "test"
        """))

        run1 = _run_scan(str(tmp_path), str(manifest))
        run2 = _run_scan(str(tmp_path), str(manifest))

        assert run1 == run2, "Multi-file SARIF output differs between runs"

    def test_verification_mode_no_timestamps(self, tmp_path: Path) -> None:
        """--verification-mode output contains no timestamp-like strings."""
        import json

        py_file = tmp_path / "mod.py"
        py_file.write_text("def f(): x = {}.get('k', 1)\n")

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(textwrap.dedent("""\
            tiers:
              - id: "EXTERNAL_RAW"
                tier: 4
            module_tiers:
              - path: "."
                default_taint: "EXTERNAL_RAW"
            metadata:
              organisation: "test"
        """))

        sarif_str = _run_scan(str(tmp_path), str(manifest))
        sarif = json.loads(sarif_str)

        import re

        # No timestamp keys in the run
        run = sarif["runs"][0]
        invocations = run.get("invocations", [{}])
        if invocations:
            assert "startTimeUtc" not in invocations[0]
        # The raw JSON should not contain ISO-8601 timestamp patterns
        # (e.g. "2024-01-01T00:00:00Z" or "2024-01-01T12:34:56+00:00")
        assert not re.search(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", sarif_str
        ), f"Found ISO-8601 timestamp in verification-mode output"
