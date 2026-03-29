"""Tests for wardline regime status / wardline regime verify commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.regime_cmd import regime
from wardline.manifest import regime as regime_mod

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "governance"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _pin_today(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin today to 2026-03-24 for deterministic age calculations."""
    from datetime import date

    monkeypatch.setattr(regime_mod, "_TODAY", date(2026, 3, 24))


# ── Helpers ────────────────────────────────────────────────────────


def _invoke_status(
    runner: CliRunner,
    *extra_args: str,
    manifest: str | None = None,
    path: str | None = None,
):
    """Invoke ``regime status`` with default fixture paths unless overridden."""
    args = [
        "status",
        "--manifest", manifest or str(FIXTURES / "wardline.yaml"),
        "--path", path or str(FIXTURES / "src"),
        *extra_args,
    ]
    return runner.invoke(regime, args, catch_exceptions=True)


def _invoke_verify(
    runner: CliRunner,
    *extra_args: str,
    manifest: str | None = None,
    path: str | None = None,
):
    """Invoke ``regime verify`` with default fixture paths unless overridden."""
    args = [
        "verify",
        "--manifest", manifest or str(FIXTURES / "wardline.yaml"),
        "--path", path or str(FIXTURES / "src"),
        *extra_args,
    ]
    return runner.invoke(regime, args, catch_exceptions=True)


def _write_minimal_manifest(tmp_path: Path) -> Path:
    """Write a minimal valid wardline.yaml and return its path."""
    manifest_yaml = tmp_path / "wardline.yaml"
    manifest_yaml.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        "  organisation: test\n"
        "  ratified_by:\n"
        '    name: "reviewer"\n'
        '    role: "lead"\n'
        '  ratification_date: "2026-03-01"\n'
        "  review_interval_days: 180\n"
        "tiers:\n"
        '  - id: "ASSURED"\n'
        "    tier: 1\n"
        '    description: "strict"\n'
        '  - id: "EXTERNAL_RAW"\n'
        "    tier: 4\n"
        '    description: "lax"\n'
        "module_tiers:\n"
        '  - path: "src/"\n'
        '    default_taint: "ASSURED"\n'
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides: []\n"
    )
    return manifest_yaml


def _write_tier_downgrade_fixture(tmp_path: Path) -> Path:
    """Write manifest + baseline that triggers tier_downgrade coherence error.

    Baseline: src/ had default_taint="ASSURED" (tier 1).
    Current:  src/ has default_taint="EXTERNAL_RAW" (tier 4).
    """
    manifest_yaml = tmp_path / "wardline.yaml"
    manifest_yaml.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        "  organisation: test\n"
        "  ratified_by:\n"
        '    name: "reviewer"\n'
        '    role: "lead"\n'
        '  ratification_date: "2026-03-01"\n'
        "  review_interval_days: 180\n"
        "tiers:\n"
        '  - id: "ASSURED"\n'
        "    tier: 1\n"
        '    description: "strict"\n'
        '  - id: "EXTERNAL_RAW"\n'
        "    tier: 4\n"
        '    description: "lax"\n'
        "module_tiers:\n"
        '  - path: "src/"\n'
        '    default_taint: "EXTERNAL_RAW"\n'
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides: []\n"
    )
    (tmp_path / "wardline.manifest.baseline.json").write_text(
        json.dumps({
            "tiers": [
                {"id": "ASSURED", "tier": 1, "description": "strict"},
                {"id": "EXTERNAL_RAW", "tier": 4, "description": "lax"},
            ],
            "module_tiers": [
                {"path": "src/", "default_taint": "ASSURED"},
            ],
        })
    )
    return manifest_yaml


# ── Test cases ─────────────────────────────────────────────────────


class TestRegimeStatusTextOutput:
    """test_regime_status_text_output — fixture produces design spec format."""

    def test_regime_status_text_output(self, runner: CliRunner) -> None:
        result = _invoke_status(runner)
        assert result.exit_code == 0, f"stderr: {result.output}"
        assert "Wardline Regime Status" in result.output
        assert "Governance profile:" in result.output
        assert "lite" in result.output
        assert "Rules:" in result.output
        assert "Exceptions:" in result.output
        assert "Fingerprint baseline:" in result.output
        assert "Manifest ratification:" in result.output
        assert "To gate on governance health, use: wardline regime verify --gate" in result.output


class TestRegimeStatusJsonOutput:
    """test_regime_status_json_output — --json produces all IRAP-required fields."""

    def test_regime_status_json_output(self, runner: CliRunner) -> None:
        result = _invoke_status(runner, "--json")
        assert result.exit_code == 0, f"output: {result.output}"
        data = json.loads(result.output)
        # All IRAP-required fields present
        assert "governance_profile" in data
        assert "analysis_level" in data
        assert "exception_counts" in data
        assert "expedited_ratio" in data
        assert "fingerprint_coverage" in data
        assert "ratification_overdue" in data
        # Verify values
        assert data["governance_profile"] == "lite"
        assert isinstance(data["exception_counts"], dict)
        assert isinstance(data["fingerprint_coverage"], dict)


class TestRegimeStatusMissingExceptions:
    """test_regime_status_missing_exceptions — no exceptions file -> zeros."""

    def test_regime_status_missing_exceptions(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")

        result = _invoke_status(
            runner, manifest=str(manifest_yaml), path=str(src_dir)
        )
        assert result.exit_code == 0
        assert "Active:              0" in result.output


class TestRegimeStatusMissingFingerprint:
    """test_regime_status_missing_fingerprint — no baseline -> 'not present'."""

    def test_regime_status_missing_fingerprint(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")

        result = _invoke_status(
            runner, manifest=str(manifest_yaml), path=str(src_dir)
        )
        assert result.exit_code == 0
        assert "not present" in result.output


class TestRegimeVerifyAllPass:
    """test_regime_verify_all_pass — clean fixture -> exit 0."""

    def test_regime_verify_all_pass(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")
        # Add perimeter baseline to avoid first_scan_perimeter warning
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        # Add fingerprint baseline
        (tmp_path / "wardline.fingerprint.json").write_text(
            json.dumps({
                "schema_version": "1.0",
                "generated_at": "2026-03-22T00:00:00Z",
                "python_version": "3.12",
                "coverage": {
                    "annotated": 0,
                    "total": 0,
                    "ratio": 0.0,
                },
                "entries": [],
            })
        )
        # Config with no disabled rules
        (tmp_path / "wardline.toml").write_text(
            "[wardline]\ndisabled_rules = []\n"
        )

        result = _invoke_verify(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0, f"output: {result.output}"
        assert "FAIL" not in result.output or "0 error" in result.output


class TestRegimeVerifyGateOnCoherenceError:
    """test_regime_verify_gate_on_coherence_error — tier downgrade + --gate -> exit 1."""

    def test_regime_verify_gate_on_coherence_error(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_tier_downgrade_fixture(tmp_path)
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "__init__.py").write_text("")

        result = _invoke_verify(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 1


class TestRegimeVerifyGateOnUnconditionalDisabled:
    """test_regime_verify_gate_on_unconditional_disabled — UNCONDITIONAL rule disabled + --gate -> exit 1."""

    def test_regime_verify_gate_on_unconditional_disabled(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        # Disable an UNCONDITIONAL rule (PY-WL-008)
        (tmp_path / "wardline.toml").write_text(
            '[wardline]\ndisabled_rules = ["PY-WL-008"]\n'
        )

        result = _invoke_verify(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 1
        assert "PY-WL-008" in result.output


class TestRegimeVerifyGateOnUnconditionalException:
    """test_regime_verify_gate_on_unconditional_exception — exception targets UNCONDITIONAL cell + --gate -> exit 1."""

    def test_regime_verify_gate_on_unconditional_exception(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        # Write an exception that targets an UNCONDITIONAL cell.
        # PY-WL-008 at UNKNOWN_RAW is UNCONDITIONAL.
        # load_exceptions will reject this at schema validation.
        (tmp_path / "wardline.exceptions.json").write_text(
            json.dumps({
                "$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json",
                "exceptions": [
                    {
                        "id": "EXC-BAD",
                        "rule": "PY-WL-008",
                        "taint_state": "UNKNOWN_RAW",
                        "location": "src/app.py::plain",
                        "exceptionability": "UNCONDITIONAL",
                        "severity_at_grant": "ERROR",
                        "rationale": "Bad exception.",
                        "reviewer": "nobody",
                        "expires": "2027-01-01",
                        "provenance": None,
                        "agent_originated": False,
                        "ast_fingerprint": "",
                        "recurrence_count": 0,
                        "governance_path": "standard",
                        "last_refreshed_by": None,
                        "last_refresh_rationale": None,
                        "last_refreshed_at": None,
                    }
                ],
            })
        )

        result = _invoke_verify(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        # Exception register validation should fail (UNCONDITIONAL target)
        assert result.exit_code == 1


class TestRegimeVerifyGatePassesOnWarnings:
    """test_regime_verify_gate_passes_on_warnings — warnings only + --gate -> exit 0."""

    def test_regime_verify_gate_passes_on_warnings(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain(): ...\n")
        # No perimeter baseline -> first_scan_perimeter WARNING (not ERROR)
        # No fingerprint baseline -> WARNING
        # No wardline.toml -> rule metrics defaults (no unconditional disabled)

        result = _invoke_verify(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        # Should pass gate — only warnings, no ERROR-level failures
        assert result.exit_code == 0, f"output: {result.output}"


class TestRegimeVerifyJsonWithCheckResults:
    """test_regime_verify_json_with_check_results — --json has check pass/fail + evidence."""

    def test_regime_verify_json_with_check_results(
        self, runner: CliRunner
    ) -> None:
        result = _invoke_verify(runner, "--json")
        assert result.exit_code == 0, f"output: {result.output}"
        data = json.loads(result.output)
        assert "checks" in data
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) > 0
        for check in data["checks"]:
            assert "check" in check
            assert "passed" in check
            assert isinstance(check["passed"], bool)
            assert "severity" in check
            assert check["severity"] in ("ERROR", "WARNING")
            assert "evidence" in check


class TestManifestMetricsFields:
    def test_ratified_by_present_when_set(self, tmp_path: Path) -> None:
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = _write_minimal_manifest(tmp_path)
        m = collect_manifest_metrics(manifest)
        assert m.ratified_by_present is True

    def test_ratified_by_present_when_missing(self, tmp_path: Path) -> None:
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.ratified_by_present is False

    def test_temporal_separation_posture_with_alternative(self, tmp_path: Path) -> None:
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "    retrospective_window_days: 10\n"
            "    rationale: small team\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture == "alternative:same-actor-with-retrospective"

    def test_temporal_separation_posture_enforced(self, tmp_path: Path) -> None:
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture == "enforced"

    def test_temporal_separation_posture_undeclared(self, tmp_path: Path) -> None:
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture is None


class TestVerifyLiteGovernanceChecks:
    """Tests for Gap 5 regime verify checks (MAN-007/009/010/011)."""

    def test_ratification_metadata_present_passes(self, runner: CliRunner, tmp_path: Path) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is True

    def test_ratification_metadata_present_fails_missing_ratified_by(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            '  ratification_date: "2026-03-01"\n'
            "  review_interval_days: 180\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is False
        assert "ratified_by" in check["evidence"]

    def test_ratification_metadata_present_fails_missing_date(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  ratified_by:\n"
            '    name: "lead"\n'
            '    role: "tech"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is False
        assert "ratification_date" in check["evidence"]

    def test_temporal_separation_declared_lite_with_alternative(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "    retrospective_window_days: 10\n"
            "    rationale: small team\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is True

    def test_temporal_separation_declared_lite_enforced(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is True

    def test_temporal_separation_declared_lite_undeclared(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is False
        assert "not declared" in check["evidence"]

    def test_annotation_change_tracking_with_baseline(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        (tmp_path / "wardline.fingerprint.json").write_text('{"coverage": {}}')
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "annotation_change_tracking")
        assert check["passed"] is True

    def test_annotation_change_tracking_no_baseline(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "annotation_change_tracking")
        assert check["passed"] is False
