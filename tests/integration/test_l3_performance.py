"""L3 call-graph taint performance test.

Runs the self-hosting scan at analysis_level=3 and asserts that
wall-clock time stays within budget (30 seconds).
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

_REPO_ROOT = Path(__file__).parent.parent.parent
_MANIFEST = _REPO_ROOT / "wardline.yaml"
_CONFIG = _REPO_ROOT / "wardline.toml"


@pytest.mark.integration
class TestL3Performance:
    """L3 analysis completes within acceptable time budget."""

    def test_l3_scan_under_30s(self) -> None:
        """Self-hosting scan at analysis_level=3 finishes in < 30 seconds."""
        from wardline.cli.main import cli

        # Create temporary config in repo root with analysis_level=3
        # (must be in repo root so relative paths resolve correctly)
        tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="w", suffix=".toml", delete=False, prefix="wardline_perf_",
            dir=_REPO_ROOT,
        )
        tmp.write(_CONFIG.read_text())
        tmp.write("\nanalysis_level = 3\n")
        tmp.close()
        config_path = Path(tmp.name)

        try:
            runner = CliRunner()
            start = time.perf_counter()
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(_REPO_ROOT / "src" / "wardline"),
                    "--manifest",
                    str(_MANIFEST),
                    "--config",
                    str(config_path),
                    "--verification-mode",
                ],
                catch_exceptions=False,
            )
            elapsed = time.perf_counter() - start

            # Scanner should not have config errors (exit 2)
            # Valid scan exit codes are 0 (clean) or 1 (findings present)
            assert result.exit_code in (0, 1), (
                f"Scan failed with exit code {result.exit_code}"
            )

            assert elapsed < 30.0, (
                f"L3 self-hosting scan took {elapsed:.1f}s, "
                f"exceeding 30s budget"
            )
        finally:
            config_path.unlink(missing_ok=True)
