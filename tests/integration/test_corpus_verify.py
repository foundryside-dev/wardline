"""Integration tests for ``wardline corpus verify`` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.manifest.loader import make_wardline_loader

FIXTURE_CORPUS = (
    Path(__file__).parent.parent / "fixtures" / "corpus"
)


@pytest.mark.integration
class TestCorpusVerifyIntegration:
    """End-to-end tests for corpus verify."""

    def test_verify_fixture_corpus(self) -> None:
        """Run verify on fixture corpus and check output."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
        )
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "Lite bootstrap:" in result.output
        # Should report at least 1 specimen
        assert "Lite bootstrap: 0 specimens" not in result.output

    def test_verify_help(self) -> None:
        """Verify --help works for corpus verify."""
        runner = CliRunner()
        result = runner.invoke(cli, ["corpus", "verify", "--help"])
        assert result.exit_code == 0
        assert "--corpus-dir" in result.output


@pytest.mark.integration
class TestRealCorpusVerify:
    """Run corpus verify against the real corpus/ directory."""

    _CORPUS_ROOT = Path(__file__).parent.parent.parent / "corpus"

    def test_real_corpus_verify_passes(self) -> None:
        """corpus verify exits 0 on the real corpus."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(self._CORPUS_ROOT)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, (
            f"corpus verify failed (exit {result.exit_code}):\n{result.output}"
        )

    def test_real_corpus_verify_level3_passes(self) -> None:
        """corpus verify at analysis level 3 includes L3 specimens."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(self._CORPUS_ROOT),
             "--analysis-level", "3"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, (
            f"corpus verify --analysis-level 3 failed (exit {result.exit_code}):\n"
            f"{result.output}"
        )
        assert "skipped" not in result.output, (
            "L3 specimens should not be skipped at analysis level 3"
        )

    def test_real_corpus_has_minimum_specimens(self) -> None:
        """Real corpus has at least 200 specimens across rules."""
        specimen_count = len(
            list((self._CORPUS_ROOT / "specimens").glob("**/positive/*.py"))
            + list((self._CORPUS_ROOT / "specimens").glob("**/negative/*.py"))
        )
        assert specimen_count >= 200, (
            f"Only {specimen_count} specimen .py files — expected >= 200"
        )

    def test_real_corpus_covers_all_9_rules(self) -> None:
        """Every PY-WL rule 001-009 has at least one specimen."""
        specimens_dir = self._CORPUS_ROOT / "specimens"
        for i in range(1, 10):
            rule_dir = specimens_dir / f"PY-WL-{i:03d}"
            assert rule_dir.is_dir(), f"Missing corpus directory for PY-WL-{i:03d}"
            py_files = list(rule_dir.glob("**/*.py"))
            assert len(py_files) >= 2, (
                f"PY-WL-{i:03d} has only {len(py_files)} specimen .py files — "
                f"expected >= 2 (at least one TP and one TN)"
            )

    def test_real_corpus_zero_location_mismatches(self) -> None:
        """corpus verify --json reports zero location mismatches."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(self._CORPUS_ROOT), "--json"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, (
            f"corpus verify --json failed (exit {result.exit_code}):\n{result.output}"
        )
        # CliRunner mixes stderr (notices/warnings) into output.
        # Extract JSON by finding the opening brace.
        output = result.output
        json_start = output.index("{")
        data = json.loads(output[json_start:])
        total_mismatches = data["summary"]["total_location_mismatches"]
        assert total_mismatches == 0, (
            f"Expected 0 location mismatches, got {total_mismatches}"
        )

    def test_migrated_specimens_structural_integrity(self) -> None:
        """Every TP specimen with structured expected_match has valid fields."""
        Loader = make_wardline_loader()
        specimens_dir = self._CORPUS_ROOT / "specimens"
        invalid: list[str] = []

        for yaml_path in sorted(specimens_dir.glob("**/positive/*.yaml")):
            with open(yaml_path) as f:
                data = yaml.load(f, Loader=Loader)  # noqa: S506
            em = data.get("expected_match")
            if not isinstance(em, dict):
                continue  # boolean — skip (covered by coverage test)
            if not isinstance(em.get("line"), int) or em["line"] < 1:
                invalid.append(f"{yaml_path.name}: line={em.get('line')}")
            if not isinstance(em.get("text"), str) or not em["text"].strip():
                invalid.append(f"{yaml_path.name}: text={em.get('text')!r}")

        assert not invalid, (
            f"{len(invalid)} specimens have invalid structured expected_match: "
            f"{invalid[:10]}"
        )
