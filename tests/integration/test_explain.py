"""Integration tests for wardline explain command."""

from __future__ import annotations

import json
import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from click.testing import CliRunner

from wardline.cli.main import cli


@pytest.mark.integration
class TestExplainDecorated:
    """Explain shows decorator-based taint resolution."""

    def test_decorated_function(self, tmp_path: Path) -> None:
        """A function with @external_boundary shows decorator resolution."""
        py_file = tmp_path / "service.py"
        py_file.write_text(
            textwrap.dedent("""\
                from wardline.decorators.authority import external_boundary

                @external_boundary
                def ingest(data):
                    return data
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "ingest", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        assert "EXTERNAL_RAW" in result.output
        assert "decorator" in result.output.lower()
        assert "external_boundary" in result.output


@pytest.mark.integration
class TestExplainUndeclaredModule:
    """Explain shows UNKNOWN_RAW for undeclared modules."""

    def test_undeclared_module_no_manifest(self, tmp_path: Path) -> None:
        """A function with no manifest shows UNKNOWN_RAW fallback."""
        py_file = tmp_path / "unknown_module.py"
        py_file.write_text(
            textwrap.dedent("""\
                def helper():
                    pass
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "helper", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        assert "UNKNOWN_RAW" in result.output
        assert "no manifest loaded" in result.output.lower()

    def test_undeclared_module_with_manifest(self, tmp_path: Path) -> None:
        """A function in a module not in module_tiers shows UNKNOWN_RAW."""
        py_file = tmp_path / "unknown_module.py"
        py_file.write_text(
            textwrap.dedent("""\
                def helper():
                    pass
            """)
        )

        # Create a minimal valid manifest that doesn't cover this module
        manifest_file = tmp_path / "wardline.yaml"
        manifest_file.write_text(
            textwrap.dedent("""\
                $id: "https://wardline.dev/schemas/1.0/wardline"
                tiers:
                  - id: core
                    tier: 1
                    description: Core tier
                module_tiers:
                  - path: /some/other/path
                    default_taint: ASSURED
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "helper",
                "--path",
                str(tmp_path),
                "--manifest",
                str(manifest_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "UNKNOWN_RAW" in result.output
        assert "module not declared" in result.output.lower()

    def test_schema_invalid_manifest_exits_config_error(
        self, tmp_path: Path
    ) -> None:
        """Schema-invalid manifest should fail instead of being downgraded to a warning."""
        py_file = tmp_path / "unknown_module.py"
        py_file.write_text(
            textwrap.dedent("""\
                def helper():
                    pass
            """)
        )

        manifest_file = tmp_path / "wardline.yaml"
        manifest_file.write_text(
            textwrap.dedent("""\
                module_tiers:
                  - path: "src/"
                    default_taint: "NOT_A_REAL_TAINT"
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "helper",
                "--path",
                str(tmp_path),
                "--manifest",
                str(manifest_file),
            ],
        )

        assert result.exit_code == 2
        assert "error: malformed manifest:" in result.stderr


@pytest.mark.integration
class TestExplainUnresolvedDecorator:
    """Explain shows unresolved decorator info."""

    def test_unresolved_decorator(self, tmp_path: Path) -> None:
        """A function with an unknown wardline decorator reports it."""
        py_file = tmp_path / "deco_test.py"
        py_file.write_text(
            textwrap.dedent("""\
                from wardline.decorators.authority import external_boundary
                from wardline.decorators.integrity import integrity_critical

                @external_boundary
                @integrity_critical
                def process(data):
                    return data
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "process", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        # Should show EXTERNAL_RAW from external_boundary
        assert "EXTERNAL_RAW" in result.output
        assert "decorator" in result.output.lower()
        # integrity_critical is not in DECORATOR_TAINT_MAP but IS in registry,
        # so it appears as an unresolved decorator
        assert "unresolved" in result.output.lower()
        assert "integrity_critical" in result.output


@pytest.mark.integration
class TestExplainNotFound:
    """Explain exits 1 for unknown functions."""

    def test_function_not_found(self, tmp_path: Path) -> None:
        """A nonexistent function produces exit 1."""
        py_file = tmp_path / "empty.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "nonexistent", "--path", str(tmp_path)]
        )

        assert result.exit_code == 1
        assert "not found" in result.output


# ── Helper to build a governance fixture for explain tests ────────────


def _build_governance_fixture(tmp_path: Path, *, with_overlay: bool = False) -> dict:
    """Build a minimal governance fixture for explain extension tests.

    Returns dict with keys: manifest_path, src_dir, py_file, exceptions_path.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    py_file = src_dir / "example.py"
    py_file.write_text(
        textwrap.dedent("""\
            from wardline.decorators.authority import external_boundary
            from wardline.decorators.validation import validates_shape
            from wardline.decorators.data_access import integral_read
            from wardline import schema_default

            @external_boundary
            def fetch_data(url: str) -> dict:
                return {}

            @validates_shape
            def check_schema(data: dict) -> bool:
                if not isinstance(data, dict):
                    raise ValueError("not a dict")
                return True

            def governed_default(data: dict) -> str:
                return schema_default(data.get("key", ""))

            @integral_read
            def get_config() -> dict:
                return {"key": "value"}
        """)
    )

    manifest_file = tmp_path / "wardline.yaml"
    manifest_file.write_text(
        textwrap.dedent("""\
            $id: "https://wardline.dev/schemas/1.0/wardline"
            tiers:
              - id: "tier1-audit"
                tier: 1
                description: "Tier 1 — audit trail data"
              - id: "tier4-external"
                tier: 4
                description: "Tier 4 — external raw input"
            module_tiers:
              - path: "src/"
                default_taint: "ASSURED"
            delegation:
              default_authority: "RELAXED"
            rules:
              overrides: []
        """)
    )

    exceptions_file = tmp_path / "wardline.exceptions.json"
    exceptions_file.write_text(
        json.dumps(
            {
                "$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json",
                "exceptions": [
                    {
                        "id": "EXC-001",
                        "rule": "PY-WL-001",
                        "taint_state": "EXTERNAL_RAW",
                        "location": "src/example.py::fetch_data",
                        "exceptionability": "STANDARD",
                        "severity_at_grant": "ERROR",
                        "rationale": "Boundary function handles raw input by design.",
                        "reviewer": "test-reviewer",
                        "expires": "2027-01-01",
                        "provenance": None,
                        "agent_originated": False,
                        "ast_fingerprint": "test_fixture_fp",
                        "recurrence_count": 0,
                        "governance_path": "standard",
                        "last_refreshed_by": None,
                        "last_refresh_rationale": None,
                        "last_refreshed_at": None,
                    },
                ],
            },
            indent=2,
        )
    )

    result = {
        "manifest_path": str(manifest_file),
        "src_dir": src_dir,
        "py_file": py_file,
        "exceptions_path": exceptions_file,
    }

    if with_overlay:
        # Overlay must be inside a module_tiers directory for discover_overlays
        overlay_file = src_dir / "wardline.overlay.yaml"
        overlay_file.write_text(
            textwrap.dedent("""\
                $id: "https://wardline.dev/schemas/1.0/overlay.schema.json"
                overlay_for: "src/"
                boundaries:
                  - function: "fetch_data"
                    transition: "shape_validation"
                    from_tier: 4
                    to_tier: 3
                  - function: "governed_default"
                    transition: "shape_validation"
                    from_tier: 4
                    to_tier: 3
                optional_fields:
                  - field: "key"
                    approved_default: ""
                    rationale: "Governed default in validation boundary"
            """)
        )
        result["overlay_path"] = overlay_file

    return result


# ── Test: Exception status section ────────────────────────────────────


@pytest.mark.integration
class TestExplainExceptionStatus:
    """Explain shows exception status per rule."""

    def test_explain_shows_exception_status(self, tmp_path: Path) -> None:
        """Function with an exception shows exception details."""
        fixture = _build_governance_fixture(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Exceptions:" in result.output
        assert "EXC-001" in result.output
        assert "active" in result.output
        assert "2027-01-01" in result.output
        assert "test-reviewer" in result.output
        assert "standard" in result.output
        assert "Recurrence: 0" in result.output

    def test_explain_shows_mixed_exceptions(self, tmp_path: Path) -> None:
        """Function with exception on PY-WL-001 but not PY-WL-003 shows mixed output."""
        fixture = _build_governance_fixture(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        # PY-WL-001 has an exception
        assert "EXC-001" in result.output
        # PY-WL-003 does not — should show (no exception)
        assert "(no exception)" in result.output

    def test_explain_shows_no_exception(self, tmp_path: Path) -> None:
        """Function with no exceptions shows (no exception) for all rules."""
        fixture = _build_governance_fixture(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "check_schema",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Exceptions:" in result.output
        # check_schema has no exceptions at all
        assert "(no exception)" in result.output
        # No exception IDs should appear
        assert "EXC-" not in result.output


# ── Test: Overlay resolution section ──────────────────────────────────


@pytest.mark.integration
class TestExplainOverlay:
    """Explain shows overlay resolution."""

    def test_explain_shows_overlay(self, tmp_path: Path) -> None:
        """Function in overlay scope shows overlay path and boundaries."""
        fixture = _build_governance_fixture(tmp_path, with_overlay=True)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Overlay:" in result.output
        assert "Governed by:" in result.output
        assert "shape_validation" in result.output
        assert "schema_default() status:" in result.output

    def test_explain_shows_no_overlay(self, tmp_path: Path) -> None:
        """Function outside overlays shows none."""
        fixture = _build_governance_fixture(tmp_path)
        # No overlay created — default fixture has no overlay

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Overlay: none" in result.output

    def test_explain_json_reports_exact_schema_default_governance(self, tmp_path: Path) -> None:
        """Overlay JSON reflects actual schema_default governance, not scope alone."""
        fixture = _build_governance_fixture(tmp_path, with_overlay=True)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "governed_default",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["overlay"]["schema_default_governed"] is True
        assert data["overlay"]["schema_default_ungoverned"] is False
        assert data["overlay"]["schema_default_calls"] == 1

    def test_explain_does_not_match_sibling_overlay_prefix(self, tmp_path: Path) -> None:
        src_api = tmp_path / "src" / "api"
        src_api.mkdir(parents=True)
        src_apiary = tmp_path / "src" / "apiary"
        src_apiary.mkdir(parents=True)

        (src_apiary / "service.py").write_text(
            textwrap.dedent("""\
                def helper():
                    return 1
            """)
        )
        (tmp_path / "wardline.yaml").write_text(
            textwrap.dedent("""\
                $id: "https://wardline.dev/schemas/1.0/wardline"
                tiers:
                  - id: "tier4-external"
                    tier: 4
                    description: "Tier 4"
                module_tiers:
                  - path: "src/"
                    default_taint: "EXTERNAL_RAW"
            """)
        )
        (src_api / "wardline.overlay.yaml").write_text(
            textwrap.dedent("""\
                $id: "https://wardline.dev/schemas/1.0/overlay.schema.json"
                overlay_for: "src/api/"
                boundaries:
                  - function: "something"
                    transition: "shape_validation"
                    from_tier: 4
                    to_tier: 3
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "helper",
                "--path",
                str(tmp_path),
                "--manifest",
                str(tmp_path / "wardline.yaml"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Overlay: none" in result.output


# ── Test: Fingerprint state section ───────────────────────────────────


@pytest.mark.integration
class TestExplainFingerprint:
    """Explain shows fingerprint state."""

    def test_explain_shows_fingerprint_match(self, tmp_path: Path) -> None:
        """Baseline matches current annotation hash -> 'yes'."""
        fixture = _build_governance_fixture(tmp_path)

        # First compute the actual fingerprint for fetch_data
        from wardline.manifest.loader import load_manifest
        from wardline.scanner.fingerprint import compute_single_annotation_fingerprint

        manifest_model = load_manifest(fixture["src_dir"].parent / "wardline.yaml")
        entry = compute_single_annotation_fingerprint(
            fixture["py_file"], "fetch_data", manifest_model
        )
        assert entry is not None

        # Write a baseline that matches
        baseline = {
            "schema_version": "1.0",
            "generated_at": "2026-03-22T00:00:00Z",
            "python_version": "3.12",
            "coverage": {
                "annotated": 3,
                "total": 3,
                "ratio": 1.0,
                "tier1_annotated": 1,
                "tier1_total": 1,
                "tier1_unannotated": [],
            },
            "entries": [
                {
                    "qualified_name": "fetch_data",
                    "module": "src/example.py",
                    "decorators": ["external_boundary"],
                    "annotation_hash": entry.annotation_hash,
                    "tier_context": 4,
                    "boundary_transition": "ingress",
                    "last_changed": "2026-03-22",
                },
            ],
        }
        baseline_path = tmp_path / "wardline.fingerprint.json"
        baseline_path.write_text(json.dumps(baseline, indent=2))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Fingerprint:" in result.output
        assert "Annotation hash:" in result.output
        assert entry.annotation_hash in result.output
        assert "yes" in result.output.lower()

    def test_explain_shows_fingerprint_mismatch(self, tmp_path: Path) -> None:
        """Baseline differs from current -> 'MODIFIED'."""
        fixture = _build_governance_fixture(tmp_path)

        # Write a baseline with a wrong hash
        baseline = {
            "schema_version": "1.0",
            "generated_at": "2026-03-22T00:00:00Z",
            "python_version": "3.12",
            "coverage": {
                "annotated": 1,
                "total": 1,
                "ratio": 1.0,
                "tier1_annotated": 0,
                "tier1_total": 0,
                "tier1_unannotated": [],
            },
            "entries": [
                {
                    "qualified_name": "fetch_data",
                    "module": "src/example.py",
                    "decorators": ["external_boundary"],
                    "annotation_hash": "0000000000000000",
                    "tier_context": 4,
                    "boundary_transition": "ingress",
                    "last_changed": "2026-03-22",
                },
            ],
        }
        baseline_path = tmp_path / "wardline.fingerprint.json"
        baseline_path.write_text(json.dumps(baseline, indent=2))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "MODIFIED" in result.output

    def test_explain_shows_no_baseline(self, tmp_path: Path) -> None:
        """No baseline file -> 'no baseline stored'."""
        fixture = _build_governance_fixture(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
            ],
        )

        assert result.exit_code == 0, result.output
        assert "no baseline stored" in result.output


# ── Test: JSON output mode ────────────────────────────────────────────


@pytest.mark.integration
class TestExplainJson:
    """Explain --json returns complete structured object."""

    def test_explain_json_output(self, tmp_path: Path) -> None:
        """--json returns JSON with all sections."""
        fixture = _build_governance_fixture(tmp_path, with_overlay=True)

        # Create a baseline for fingerprint section
        from wardline.manifest.loader import load_manifest
        from wardline.scanner.fingerprint import compute_single_annotation_fingerprint

        manifest_model = load_manifest(fixture["src_dir"].parent / "wardline.yaml")
        entry = compute_single_annotation_fingerprint(
            fixture["py_file"], "fetch_data", manifest_model
        )
        assert entry is not None

        baseline = {
            "schema_version": "1.0",
            "generated_at": "2026-03-22T00:00:00Z",
            "python_version": "3.12",
            "coverage": {
                "annotated": 1,
                "total": 1,
                "ratio": 1.0,
                "tier1_annotated": 0,
                "tier1_total": 0,
                "tier1_unannotated": [],
            },
            "entries": [
                {
                    "qualified_name": "fetch_data",
                    "module": "src/example.py",
                    "decorators": ["external_boundary"],
                    "annotation_hash": entry.annotation_hash,
                    "tier_context": 4,
                    "boundary_transition": "ingress",
                    "last_changed": "2026-03-22",
                },
            ],
        }
        baseline_path = tmp_path / "wardline.fingerprint.json"
        baseline_path.write_text(json.dumps(baseline, indent=2))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(tmp_path),
                "--manifest",
                fixture["manifest_path"],
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)

        # Top-level fields
        assert data["qualname"] == "fetch_data"
        assert "EXTERNAL_RAW" in data["taint_state"]
        assert data["resolution"]["source"] == "decorator"

        # Rules section
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) > 0

        # Exceptions section
        assert isinstance(data["exceptions"], list)
        # Should have one active exception for PY-WL-001
        active_exc = [e for e in data["exceptions"] if e.get("id") is not None]
        assert len(active_exc) >= 1
        assert active_exc[0]["id"] == "EXC-001"

        # Overlay section
        assert data["overlay"] is not None
        assert "schema_default_governed" in data["overlay"]

        # Fingerprint section
        assert data["fingerprint"] is not None
        assert data["fingerprint"]["annotation_hash"] == entry.annotation_hash
        assert data["fingerprint"]["baseline_match"] is True
