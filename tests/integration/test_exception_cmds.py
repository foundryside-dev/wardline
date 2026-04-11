"""Integration tests for wardline exception CLI commands."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path


def _make_project(tmp_path: Path) -> tuple[Path, Path]:
    """Create a minimal wardline project with a Python file containing a function.

    Returns (manifest_path, python_file_path).
    """
    manifest = tmp_path / "wardline.yaml"
    manifest.write_text(
        "tiers:\n"
        '  - id: "test"\n'
        "    tier: 1\n"
        '    description: "test tier"\n'
        "module_tiers: []\n"
        "metadata:\n"
        '  organisation: "TestOrg"\n'
    )
    py_file = tmp_path / "example.py"
    py_file.write_text(
        "def process_data(x):\n"
        "    return x + 1\n"
    )
    return manifest, py_file


@pytest.mark.integration
class TestExceptionAdd:
    """Tests for `wardline exception add`."""

    def test_add_creates_entry(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add creates an entry with a computed fingerprint."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        location = f"{py_file}::process_data"
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", location,
                "--taint-state", "ASSURED",
                "--rationale", "Test rationale",
                "--reviewer", "tester",
                "--governance-path", "standard",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"stdout: {result.output}\nstderr: {result.stderr}"
        assert "Added exception EXC-" in result.output

        # Verify the file was created
        exc_file = tmp_path / "wardline.exceptions.json"
        assert exc_file.exists()

        data = json.loads(exc_file.read_text())
        assert len(data["exceptions"]) == 1
        entry = data["exceptions"][0]
        assert entry["rule"] == "PY-WL-001"
        assert entry["taint_state"] == "ASSURED"
        assert entry["ast_fingerprint"] is not None
        assert len(entry["ast_fingerprint"]) == 16
        assert entry["recurrence_count"] == 0
        assert entry["governance_path"] == "standard"
        assert entry["provenance"] == "cli"

    def test_add_unconditional_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with UNCONDITIONAL rule+taint combination is refused."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        # PY-WL-001 + INTEGRAL is UNCONDITIONAL per matrix
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", f"{py_file}::process_data",
                "--taint-state", "INTEGRAL",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "UNCONDITIONAL" in result.stderr

    def test_add_invalid_rule(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with invalid rule ID is refused."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "INVALID-RULE",
                "--location", f"{py_file}::process_data",
                "--taint-state", "ASSURED",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "invalid rule ID" in result.stderr

    def test_add_bad_location_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with missing :: in location is refused."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", "no_separator",
                "--taint-state", "ASSURED",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "file_path::qualname" in result.stderr


@pytest.mark.integration
class TestExceptionRefresh:
    """Tests for `wardline exception refresh`."""

    def test_refresh_requires_actor(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh without --actor is an error."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "refresh", "EXC-12345678", "--rationale", "safe"],
        )
        assert result.exit_code != 0
        assert "actor" in (result.output + result.stderr).lower()

    def test_refresh_requires_rationale(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh without --rationale is an error."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "refresh", "EXC-12345678", "--actor", "dev"],
        )
        assert result.exit_code != 0
        assert "rationale" in (result.output + result.stderr).lower()

    def test_refresh_all_requires_confirm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh --all without --confirm is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "refresh",
                "--all", "--actor", "dev", "--rationale", "safe",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "--confirm" in result.stderr

    def test_refresh_no_ids_no_all_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh with neither IDs nor --all is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "refresh",
                "--actor", "dev", "--rationale", "safe",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "provide exception IDs" in result.stderr


@pytest.mark.integration
class TestExceptionExpire:
    """Tests for `wardline exception expire`."""

    def test_expire_sets_date(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """expire sets the expires field to today."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        # First add an exception
        runner = CliRunner()
        location = f"{py_file}::process_data"
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", location,
                "--taint-state", "ASSURED",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

        # Get the exception ID from the output
        exc_id = result.output.split("Added exception ")[1].split(" ")[0]

        # Now expire it
        result = runner.invoke(
            cli,
            ["exception", "expire", exc_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "Expired" in result.output

        # Verify the file
        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry = data["exceptions"][0]
        assert entry["expires"] is not None

    def test_expire_unknown_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """expire with unknown exception ID is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "expire", "EXC-NONEXIST"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "not found" in result.stderr


@pytest.mark.integration
class TestExceptionReview:
    """Tests for `wardline exception review`."""

    def test_review_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """review --json returns valid JSON."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "review", "--json"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "stale" in data
        assert "expired" in data
        assert "approaching_expiry" in data
        assert "unknown_provenance" in data
        assert "recurring" in data
        assert "expedited_ratio" in data
        assert "total" in data

    def test_review_text_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """review without --json shows human-readable summary."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "review"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "Exception Register Review" in result.output


# ---------------------------------------------------------------------------
# Lifecycle integration tests (from QA review panel)
# ---------------------------------------------------------------------------


def _add_exception(
    runner: CliRunner,
    py_file: Path,
    *,
    rule: str = "PY-WL-001",
    taint: str = "ASSURED",
    expires: str | None = None,
) -> str:
    """Add an exception and return the exception ID."""
    args = [
        "exception", "add",
        "--rule", rule,
        "--location", f"{py_file}::process_data",
        "--taint-state", taint,
        "--rationale", "Test rationale",
        "--reviewer", "tester",
        "--governance-path", "standard",
    ]
    if expires is not None:
        args.extend(["--expires", expires])
    result = runner.invoke(cli, args, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    # Parse "Added exception EXC-XXXXXXXX ..."
    for word in result.output.split():
        if word.startswith("EXC-"):
            return word
    raise AssertionError(f"No EXC- ID in output: {result.output}")


@pytest.mark.integration
class TestRecurrenceLifecycle:
    """Spec §10.4: recurrence tracking on exception renewal."""

    def test_add_code_change_refresh_no_increment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """add → code change → refresh does NOT increment recurrence_count.

        A refresh recomputes the fingerprint for the same exception. It
        is not a renewal — the exception continues, it just tracks that
        the code changed.
        """
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        # Step 1: add exception
        exc_id = _add_exception(runner, py_file)

        # Step 2: change code (modifies AST fingerprint)
        py_file.write_text(
            "def process_data(x):\n"
            "    y = x + 1\n"
            "    return y\n"
        )

        # Step 3: refresh
        result = runner.invoke(
            cli,
            [
                "exception", "refresh", exc_id,
                "--actor", "dev",
                "--rationale", "code changed",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

        # Verify recurrence_count is still 0
        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry = next(e for e in data["exceptions"] if e["id"] == exc_id)
        assert entry["recurrence_count"] == 0

    def test_expire_add_renewal_increments_recurrence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """expire → add renewal DOES increment recurrence_count.

        When the same (rule, location) gets a new exception after the
        prior one, recurrence_count must carry forward + 1 per spec §10.4.
        """
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        # First exception
        _add_exception(runner, py_file, expires="2026-01-01")

        # Second exception (renewal — same rule + location)
        exc_id2 = _add_exception(runner, py_file, expires="2026-06-01")

        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry2 = next(e for e in data["exceptions"] if e["id"] == exc_id2)
        assert entry2["recurrence_count"] == 1

        # Third exception (second renewal)
        exc_id3 = _add_exception(runner, py_file, expires="2026-12-01")

        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry3 = next(e for e in data["exceptions"] if e["id"] == exc_id3)
        assert entry3["recurrence_count"] == 2


@pytest.mark.integration
class TestRefreshHappyPath:
    """refresh --all --confirm updates all non-expired fingerprints."""

    def test_refresh_all_confirm_updates_fingerprints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        # Add an exception
        exc_id = _add_exception(runner, py_file)

        # Get original fingerprint
        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        original_fp = data["exceptions"][0]["ast_fingerprint"]

        # Change the code
        py_file.write_text(
            "def process_data(x):\n"
            "    result = x * 2\n"
            "    return result\n"
        )

        # Refresh all
        result = runner.invoke(
            cli,
            [
                "exception", "refresh",
                "--all", "--confirm",
                "--actor", "dev",
                "--rationale", "code restructured",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

        # Verify fingerprint changed
        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry = next(e for e in data["exceptions"] if e["id"] == exc_id)
        assert entry["ast_fingerprint"] != original_fp
        assert len(entry["ast_fingerprint"]) == 16


@pytest.mark.integration
class TestMultiFindingPartition:
    """Multiple findings in the same file matched to different exceptions."""

    def test_two_findings_two_exceptions_both_suppressed(
        self, tmp_path: Path,
    ) -> None:
        """Each finding matches its own exception independently."""
        import datetime

        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.core.taints import TaintState
        from wardline.manifest.models import ExceptionEntry
        from wardline.scanner.context import Finding
        from wardline.scanner.exceptions import apply_exceptions
        from wardline.scanner.fingerprint import compute_ast_fingerprint

        # Create a file with two functions
        py_file = tmp_path / "multi.py"
        py_file.write_text(
            "def func_a(d):\n"
            "    return d.get('key', None)\n"
            "\n"
            "def func_b(d):\n"
            "    return d.get('other', 0)\n"
        )

        fp_a = compute_ast_fingerprint(py_file, "func_a", project_root=tmp_path)
        fp_b = compute_ast_fingerprint(py_file, "func_b", project_root=tmp_path)
        assert fp_a is not None and fp_b is not None

        rel = "multi.py"
        findings = [
            Finding(
                rule_id=RuleId.PY_WL_001,
                file_path=str(py_file),
                line=2, col=11, end_line=2, end_col=30,
                message="get with default",
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=TaintState.ASSURED,
                analysis_level=1,
                source_snippet=None,
                qualname="func_a",
            ),
            Finding(
                rule_id=RuleId.PY_WL_001,
                file_path=str(py_file),
                line=5, col=11, end_line=5, end_col=28,
                message="get with default",
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=TaintState.ASSURED,
                analysis_level=1,
                source_snippet=None,
                qualname="func_b",
            ),
        ]

        exceptions = (
            ExceptionEntry(
                id="EXC-AAAA0001",
                rule="PY-WL-001",
                taint_state="ASSURED",
                location=f"{rel}::func_a",
                exceptionability="STANDARD",
                severity_at_grant="ERROR",
                rationale="accepted",
                reviewer="alice",
                ast_fingerprint=fp_a,
                expires="2027-01-01",
                recurrence_count=0,
                governance_path="standard",
                agent_originated=False,
            ),
            ExceptionEntry(
                id="EXC-BBBB0002",
                rule="PY-WL-001",
                taint_state="ASSURED",
                location=f"{rel}::func_b",
                exceptionability="STANDARD",
                severity_at_grant="ERROR",
                rationale="accepted",
                reviewer="bob",
                ast_fingerprint=fp_b,
                expires="2027-01-01",
                recurrence_count=0,
                governance_path="standard",
                agent_originated=False,
            ),
        )

        processed, governance = apply_exceptions(
            findings, exceptions, project_root=tmp_path,
            now=datetime.date(2026, 3, 26),
        )

        # Both findings should be suppressed
        suppressed = [
            f for f in processed if f.severity == Severity.SUPPRESS
        ]
        assert len(suppressed) == 2
        assert {f.exception_id for f in suppressed} == {"EXC-AAAA0001", "EXC-BBBB0002"}
