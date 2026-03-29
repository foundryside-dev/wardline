"""Tests for exception migration CLI commands (Task 9, WP 2.1).

Tests preview-drift, migrate, and grant --analysis-level.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from click.testing import CliRunner

from wardline.cli.exception_cmds import exception
from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_exceptions_file(tmp_path: Path, exceptions: list[dict[str, Any]]) -> Path:
    """Write a wardline.exceptions.json into tmp_path and return its path."""
    exc_path = tmp_path / "wardline.exceptions.json"
    data = {
        "$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json",
        "exceptions": exceptions,
    }
    exc_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return exc_path


def _read_exceptions(tmp_path: Path) -> list[dict[str, Any]]:
    """Read exceptions from the file."""
    exc_path = tmp_path / "wardline.exceptions.json"
    data = json.loads(exc_path.read_text(encoding="utf-8"))
    return data["exceptions"]


def _base_exception(
    exc_id: str = "EXC-AAAA0001",
    rule: str = "PY-WL-001",
    taint_state: str = "ASSURED",
    location: str = "src/app.py::App.handle",
    analysis_level: int = 1,
) -> dict[str, Any]:
    """Build a minimal valid exception entry."""
    return {
        "id": exc_id,
        "rule": rule,
        "taint_state": taint_state,
        "location": location,
        "exceptionability": "STANDARD",
        "severity_at_grant": "ERROR",
        "rationale": "test rationale",
        "reviewer": "tester",
        "analysis_level": analysis_level,
    }


def _mock_compute_taints(taint_results: dict[str, TaintState]):
    """Return a mock _compute_taints that returns a fixed taint map."""
    def _compute(_scan_path, _manifest_path, _analysis_level):
        return taint_results
    return _compute


# ---------------------------------------------------------------------------
# preview-drift tests
# ---------------------------------------------------------------------------


class TestPreviewDrift:
    def test_preview_drift_reports_changes(self, tmp_path: Path) -> None:
        """Exceptions at L1 taints, L3 changes some -> report."""
        exc = _base_exception(taint_state="ASSURED")
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.EXTERNAL_RAW}

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
        ):
            result = runner.invoke(exception, [
                "preview-drift",
                "--analysis-level", "3",
                "--path", str(tmp_path),
                "--json",
            ])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["count"] == 1
        assert output["drifted"][0]["old_taint"] == "ASSURED"
        assert output["drifted"][0]["new_taint"] == "EXTERNAL_RAW"

    def test_preview_drift_no_changes(self, tmp_path: Path) -> None:
        """All match -> 'no drift'."""
        exc = _base_exception(taint_state="ASSURED")
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.ASSURED}

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
        ):
            result = runner.invoke(exception, [
                "preview-drift",
                "--analysis-level", "3",
                "--path", str(tmp_path),
            ])

        assert result.exit_code == 0
        assert "No drift detected" in result.output


# ---------------------------------------------------------------------------
# migrate tests
# ---------------------------------------------------------------------------


class TestMigrate:
    def test_migrate_updates_taint_state(self, tmp_path: Path) -> None:
        """taint_state field updated in JSON."""
        exc = _base_exception(taint_state="ASSURED")
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.EXTERNAL_RAW}

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
        ):
            result = runner.invoke(exception, [
                "migrate",
                "--analysis-level", "3",
                "--path", str(tmp_path),
                "--actor", "test-user",
                "--confirm",
            ])

        assert result.exit_code == 0
        entries = _read_exceptions(tmp_path)
        assert entries[0]["taint_state"] == "EXTERNAL_RAW"

    def test_migrate_stamps_analysis_level(self, tmp_path: Path) -> None:
        """Migrated entries have analysis_level: 3."""
        exc = _base_exception(taint_state="ASSURED", analysis_level=1)
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.EXTERNAL_RAW}

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
        ):
            result = runner.invoke(exception, [
                "migrate",
                "--analysis-level", "3",
                "--path", str(tmp_path),
                "--actor", "test-user",
                "--confirm",
            ])

        assert result.exit_code == 0
        entries = _read_exceptions(tmp_path)
        assert entries[0]["analysis_level"] == 3

    def test_migrate_adds_audit_trail(self, tmp_path: Path) -> None:
        """migrated_from note added."""
        exc = _base_exception(taint_state="ASSURED", analysis_level=1)
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.EXTERNAL_RAW}

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
        ):
            result = runner.invoke(exception, [
                "migrate",
                "--analysis-level", "3",
                "--path", str(tmp_path),
                "--actor", "test-user",
                "--confirm",
            ])

        assert result.exit_code == 0
        entries = _read_exceptions(tmp_path)
        assert entries[0]["migrated_from"] == "taint_state was ASSURED at level 1"

    def test_migrate_idempotent(self, tmp_path: Path) -> None:
        """Running twice produces stable output."""
        exc = _base_exception(taint_state="ASSURED", analysis_level=1)
        _make_exceptions_file(tmp_path, [exc])

        taint_results = {"App.handle": TaintState.EXTERNAL_RAW}

        runner = CliRunner()
        exc_path = tmp_path / "wardline.exceptions.json"

        for _ in range(2):
            with (
                patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=exc_path),
                patch("wardline.cli.exception_cmds._compute_taints", side_effect=_mock_compute_taints(taint_results)),
            ):
                result = runner.invoke(exception, [
                    "migrate",
                    "--analysis-level", "3",
                    "--path", str(tmp_path),
                    "--actor", "test-user",
                    "--confirm",
                ])
            assert result.exit_code == 0

        # After second run, nothing should have changed from the first run result
        entries = _read_exceptions(tmp_path)
        assert entries[0]["taint_state"] == "EXTERNAL_RAW"
        assert entries[0]["analysis_level"] == 3
        # migrated_from should be from the first migration, not overwritten
        assert entries[0]["migrated_from"] == "taint_state was ASSURED at level 1"

    def test_migrate_requires_confirm(self, tmp_path: Path) -> None:
        """Without --confirm -> error, no file changes."""
        exc = _base_exception(taint_state="ASSURED")
        _make_exceptions_file(tmp_path, [exc])

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
        ):
            result = runner.invoke(exception, [
                "migrate",
                "--analysis-level", "3",
                "--path", str(tmp_path),
                "--actor", "test-user",
            ])

        assert result.exit_code != 0
        assert "--confirm" in result.output or "confirm" in result.output.lower()

        # File should be unchanged
        entries = _read_exceptions(tmp_path)
        assert entries[0]["taint_state"] == "ASSURED"


# ---------------------------------------------------------------------------
# grant tests
# ---------------------------------------------------------------------------


class TestGrant:
    def test_grant_with_analysis_level(self, tmp_path: Path) -> None:
        """--analysis-level 3 -> entry has analysis_level: 3."""
        _make_exceptions_file(tmp_path, [])

        runner = CliRunner()
        with (
            patch("wardline.cli.exception_cmds._find_exceptions_file", return_value=tmp_path / "wardline.exceptions.json"),
            patch("wardline.cli.exception_cmds.compute_ast_fingerprint", return_value="abcdef0123456789"),
        ):
            result = runner.invoke(exception, [
                "grant",
                "--rule", "PY-WL-003",
                "--location", "src/app.py::App.handle",
                "--taint-state", "EXTERNAL_RAW",
                "--rationale", "Test rationale",
                "--reviewer", "tester",
                "--analysis-level", "3",
            ])

        assert result.exit_code == 0, result.output
        entries = _read_exceptions(tmp_path)
        assert len(entries) == 1
        assert entries[0]["analysis_level"] == 3
        assert entries[0]["rule"] == "PY-WL-003"
