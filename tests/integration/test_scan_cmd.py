"""Integration tests for ``wardline scan`` CLI command (T-5.2).

Tests the full pipeline: manifest loading → config parsing → registry
sync → rule execution → SARIF output → exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE_PROJECT = (
    Path(__file__).parent.parent / "fixtures" / "integration" / "sample_project"
)
FIXTURE_TOML = Path(__file__).parent.parent / "fixtures" / "wardline.toml"


def _minimal_manifest(tmp_path: Path) -> Path:
    """Create a minimal valid manifest and a clean Python file."""
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
    py_file = tmp_path / "clean.py"
    py_file.write_text("x = 1\n")
    return manifest


@pytest.mark.integration
class TestScanProducesSarif:
    """Scan output is valid SARIF v2.1.0 JSON."""

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        """Scan output parses as JSON."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        assert isinstance(sarif, dict)

    def test_sarif_has_required_keys(self, tmp_path: Path) -> None:
        """SARIF output has $schema, version, runs."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_run_has_tool_and_results(self, tmp_path: Path) -> None:
        """SARIF run contains tool driver and results array."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "wardline"
        assert "results" in run

    def test_degraded_taint_is_surfaced_in_sarif_properties(
        self, tmp_path: Path
    ) -> None:
        """Pass-1 taint degradation appears in SARIF run properties/results."""
        from unittest.mock import patch

        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding
        from wardline.scanner.engine import ScanResult

        manifest = _minimal_manifest(tmp_path)
        fake_result = ScanResult(
            findings=[
                Finding(
                    rule_id=RuleId.GOVERNANCE_TAINT_DEGRADED,
                    file_path=str(tmp_path / "clean.py"),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message="Taint assignment degraded: fallback map used",
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=1,
                    source_snippet=None,
                ),
            ],
            files_scanned=1,
            files_with_degraded_taint=1,
        )

        with patch(
            "wardline.scanner.engine.ScanEngine.scan",
            return_value=fake_result,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, [
                "scan", str(tmp_path),
                "--manifest", str(manifest),
                "--allow-registry-mismatch",
            ])

        assert result.exit_code == 0  # WARNING severity — not gate-blocking
        sarif = json.loads(result.stdout)
        run = sarif["runs"][0]
        assert run["properties"]["wardline.filesWithDegradedTaint"] == 1
        degraded = [
            r for r in run["results"]
            if r["ruleId"] == "GOVERNANCE-TAINT-DEGRADED"
        ]
        assert len(degraded) == 1

    def test_dynamic_import_emits_sarif_result(self, tmp_path: Path) -> None:
        """Dynamic wardline imports are serialized as SARIF diagnostics."""
        manifest = _minimal_manifest(tmp_path)
        (tmp_path / "dyn.py").write_text(
            "import importlib\nmod = importlib.import_module('wardline')\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])

        assert result.exit_code == 0  # WARNING severity — not gate-blocking
        sarif = json.loads(result.stdout)
        dynamic_imports = [
            r for r in sarif["runs"][0]["results"]
            if r["ruleId"] == "WARDLINE-DYNAMIC-IMPORT"
        ]
        assert len(dynamic_imports) == 1

    def test_sarif_implemented_rules_matches_loaded(
        self, tmp_path: Path
    ) -> None:
        """implementedRules lists exactly the loaded rule IDs."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        implemented = sarif["runs"][0]["properties"]["wardline.implementedRules"]
        # 12 rules loaded (PY-WL-001 through PY-WL-009, SCN-021, SCN-022, SUP-001)
        assert "PY-WL-001" in implemented
        assert "PY-WL-009" in implemented
        assert "SCN-021" in implemented
        assert "SCN-022" in implemented
        assert "SUP-001" in implemented
        assert len(implemented) == 12

    def test_sarif_findings_present_for_fixture(self) -> None:
        """Scanning fixture project produces SARIF results."""
        manifest = FIXTURE_PROJECT / "wardline.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURE_PROJECT),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0

    def test_sarif_output_to_file(self, tmp_path: Path) -> None:
        """--output writes SARIF to a file instead of stdout."""
        manifest = _minimal_manifest(tmp_path)
        output_file = tmp_path / "output.sarif.json"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--output", str(output_file),
        ])
        assert result.exit_code == 0
        sarif = json.loads(output_file.read_text())
        assert sarif["version"] == "2.1.0"

    def test_output_write_error_exits_2(self, tmp_path: Path) -> None:
        """--output to nonexistent directory exits 2 with error message."""
        manifest = _minimal_manifest(tmp_path)
        bad_output = str(tmp_path / "no_such_dir" / "output.sarif.json")
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--output", bad_output,
        ])
        assert result.exit_code == 2
        assert "error:" in result.stderr
        assert "Traceback" not in (result.output + result.stderr)


@pytest.mark.integration
class TestScanExitCodes:
    """Exit code semantics for the scan command."""

    def test_exit_0_clean_scan(self, tmp_path: Path) -> None:
        """No findings → exit 0."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        assert result.exit_code == 0

    def test_exit_1_findings(self) -> None:
        """Findings present → exit 1."""
        manifest = FIXTURE_PROJECT / "wardline.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURE_PROJECT),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        assert result.exit_code == 1

    def test_exit_2_schema_invalid_manifest(self, tmp_path: Path) -> None:
        """Schema-invalid manifest → exit 2 with structured error."""
        bad_manifest = tmp_path / "wardline.yaml"
        bad_manifest.write_text("not_a_valid_key: true\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--manifest", str(bad_manifest)])
        assert result.exit_code == 2
        assert "error:" in result.stderr
        # Must NOT show a Python traceback
        assert "Traceback" not in result.output
        assert "Traceback" not in result.stderr


@pytest.mark.integration
class TestRegistrySync:
    """Registry sync check at scan startup."""

    def test_registry_mismatch_exits_2_without_flag(
        self, tmp_path: Path
    ) -> None:
        """Registry mismatch without --allow-registry-mismatch → exit 2."""
        from unittest.mock import patch

        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        # Patch make_rules to return only a subset, creating a mismatch
        # with the canonical registry (which has all 9 rules).
        with patch(
            "wardline.cli.scan.make_rules",
            return_value=(),
        ):
            result = runner.invoke(cli, [
                "scan", str(tmp_path),
                "--manifest", str(manifest),
            ])
        assert result.exit_code == 2
        assert "registry sync failed" in result.stderr

    def test_registry_mismatch_governance_with_flag(
        self, tmp_path: Path
    ) -> None:
        """Registry mismatch with flag → GOVERNANCE finding."""
        from unittest.mock import patch

        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        # Patch make_rules to return only a subset, creating a mismatch
        with patch(
            "wardline.cli.scan.make_rules",
            return_value=(),
        ):
            result = runner.invoke(cli, [
                "scan", str(tmp_path),
                "--manifest", str(manifest),
                "--allow-registry-mismatch",
            ])
        # Should succeed (no scan findings on clean code)
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        governance_results = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-REGISTRY-MISMATCH-ALLOWED"
        ]
        assert len(governance_results) > 0


@pytest.mark.integration
class TestMaxUnknownRawPercent:
    """--max-unknown-raw-percent ceiling enforcement."""

    def test_at_limit_passes(self, tmp_path: Path) -> None:
        """At or below limit → exit 0 (if no other findings)."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--max-unknown-raw-percent", "100.0",
        ])
        assert result.exit_code == 0

    def test_above_limit_exits_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Above limit → exit 1."""
        from unittest.mock import patch

        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.core.taints import TaintState
        from wardline.scanner.context import Finding
        from wardline.scanner.engine import ScanResult

        manifest = _minimal_manifest(tmp_path)

        # Patch ScanEngine.scan to return a result with UNKNOWN_RAW
        fake_result = ScanResult(
            findings=[
                Finding(
                    rule_id=RuleId.PY_WL_001,
                    file_path="fake.py",
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message="test",
                    severity=Severity.ERROR,
                    exceptionability=Exceptionability.STANDARD,
                    taint_state=TaintState.UNKNOWN_RAW,
                    analysis_level=1,
                    source_snippet=None,
                ),
            ],
            files_scanned=1,
        )

        with patch(
            "wardline.scanner.engine.ScanEngine.scan",
            return_value=fake_result,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, [
                "scan", str(tmp_path),
                "--manifest", str(manifest),
                "--allow-registry-mismatch",
                "--max-unknown-raw-percent", "0.0",
            ])
        # 100% UNKNOWN_RAW > 0.0% limit → exit 1
        assert result.exit_code == 1


@pytest.mark.integration
class TestCliOverridesToml:
    """CLI flags override wardline.toml values."""

    def test_cli_max_pct_overrides_toml(self, tmp_path: Path) -> None:
        """--max-unknown-raw-percent on CLI overrides toml value."""
        manifest = _minimal_manifest(tmp_path)

        # Create a config with max_unknown_raw_percent = 10.0
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "max_unknown_raw_percent = 10.0\n"
            "allow_registry_mismatch = true\n"
        )

        runner = CliRunner()
        # CLI says 100.0, overriding toml's 10.0
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
            "--max-unknown-raw-percent", "100.0",
        ])
        assert result.exit_code == 0

    def test_cli_allow_mismatch_overrides_toml(
        self, tmp_path: Path
    ) -> None:
        """--allow-registry-mismatch on CLI overrides toml's false."""
        manifest = _minimal_manifest(tmp_path)

        # Config does NOT set allow_registry_mismatch
        config = tmp_path / "wardline.toml"
        config.write_text("[wardline]\n")

        runner = CliRunner()
        # CLI flag enables it
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
            "--allow-registry-mismatch",
        ])
        assert result.exit_code == 0

    def test_toml_allow_mismatch_used_when_cli_absent(
        self, tmp_path: Path
    ) -> None:
        """allow_registry_mismatch from toml used when CLI doesn't set it."""
        manifest = _minimal_manifest(tmp_path)

        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "allow_registry_mismatch = true\n"
        )

        runner = CliRunner()
        # No --allow-registry-mismatch on CLI
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        # Should pass because toml enables the flag
        assert result.exit_code == 0


@pytest.mark.integration
class TestConfigValidation:
    """wardline.toml validation."""

    def test_unknown_key_exits_2(self, tmp_path: Path) -> None:
        """Unknown key in wardline.toml → exit 2."""
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            'bogus_key = "oops"\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 2
        assert "unknown keys" in result.stderr

    def test_invalid_rule_id_exits_2(self, tmp_path: Path) -> None:
        """Invalid rule ID in wardline.toml → exit 2."""
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            'enabled_rules = ["NOT-A-RULE"]\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 2
        assert "invalid rule ID" in result.stderr

    def test_invalid_taint_state_exits_2(self, tmp_path: Path) -> None:
        """Invalid taint state in wardline.toml → exit 2."""
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            'default_taint = "NOT_A_TAINT"\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 2
        assert "invalid taint state" in result.stderr


@pytest.mark.integration
class TestDisabledRules:
    """GOVERNANCE signals for disabled rules."""

    def test_disabled_rule_governance_finding(self, tmp_path: Path) -> None:
        """Disabled rule produces GOVERNANCE-RULE-DISABLED finding in SARIF."""
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "allow_registry_mismatch = true\n"
            'disabled_rules = ["PY-WL-001"]\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        gov_disabled = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-RULE-DISABLED"
        ]
        assert len(gov_disabled) == 1
        assert "PY-WL-001" in gov_disabled[0]["message"]["text"]

    def test_disabled_standard_rule_is_warning_severity(
        self, tmp_path: Path
    ) -> None:
        """Disabling a STANDARD rule produces WARNING-level GOVERNANCE."""
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "allow_registry_mismatch = true\n"
            'disabled_rules = ["PY-WL-001"]\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        gov_disabled = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-RULE-DISABLED"
        ]
        assert gov_disabled[0]["level"] == "warning"


@pytest.mark.integration
class TestPermissiveDistribution:
    """GOVERNANCE signal for permissive distribution."""

    def test_permissive_distribution_governance_finding(
        self, tmp_path: Path
    ) -> None:
        """--allow-permissive-distribution adds GOVERNANCE finding."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--allow-permissive-distribution",
        ])
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        gov_perm = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-PERMISSIVE-DISTRIBUTION"
        ]
        assert len(gov_perm) == 1


@pytest.mark.integration
class TestKnownValidatorsGovernance:
    """Governance visibility for custom known_validators config."""

    def test_known_validators_extra_emits_governance_finding(
        self, tmp_path: Path
    ) -> None:
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "allow_registry_mismatch = true\n"
            'known_validators_extra = ["mycompany.validators.check_payload"]\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        gov_custom = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-CUSTOM-KNOWN-VALIDATOR"
        ]
        assert len(gov_custom) == 1
        assert "mycompany.validators.check_payload" in gov_custom[0]["message"]["text"]

    def test_builtin_replacement_only_emits_no_custom_governance(
        self, tmp_path: Path
    ) -> None:
        manifest = _minimal_manifest(tmp_path)
        config = tmp_path / "wardline.toml"
        config.write_text(
            "[wardline]\n"
            "allow_registry_mismatch = true\n"
            'known_validators = ["jsonschema.validate"]\n'
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--config", str(config),
        ])
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        gov_custom = [
            r for r in results
            if r["ruleId"] == "GOVERNANCE-CUSTOM-KNOWN-VALIDATOR"
        ]
        assert gov_custom == []


@pytest.mark.integration
class TestPreviewPhase2Flag:
    """Smoke tests for --preview-phase2 flag."""

    def test_preview_phase2_flag_produces_json(self, tmp_path: Path) -> None:
        """--preview-phase2 produces JSON output, not SARIF."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--preview-phase2",
        ])
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}. Output: {result.output}"
        )
        report = json.loads(result.stdout)
        assert "version" in report
        assert "scan_metadata" in report
        assert report["unverified_default_count"] == 0

    def test_preview_phase2_output_to_file(self, tmp_path: Path) -> None:
        """--preview-phase2 with --output writes JSON to file."""
        manifest = _minimal_manifest(tmp_path)
        output_file = tmp_path / "preview.json"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--preview-phase2",
            "--output", str(output_file),
        ])
        assert result.exit_code == 0
        report = json.loads(output_file.read_text())
        assert "version" in report
        assert "scan_metadata" in report

    def test_preview_phase2_not_sarif(self, tmp_path: Path) -> None:
        """--preview-phase2 output does NOT contain SARIF '$schema' key."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--preview-phase2",
        ])
        assert result.exit_code == 0
        report = json.loads(result.stdout)
        assert "$schema" not in report
        assert "runs" not in report


@pytest.mark.integration
class TestScanResolved:
    """Tests for --resolved flag loading pre-resolved manifest."""

    def test_resolved_flag_loads_boundaries(self, tmp_path: Path) -> None:
        """--resolved flag loads boundaries from JSON instead of discovering."""
        manifest = _minimal_manifest(tmp_path)

        # Write a resolved JSON with one boundary
        resolved = tmp_path / "wardline.resolved.json"
        resolved.write_text(json.dumps({
            "format_version": "0.2",
            "resolved_at": "2026-01-01T00:00:00Z",
            "root": ".",
            "manifest_source": "wardline.yaml",
            "manifest_hash": "sha256:abc",
            "tiers": [],
            "module_tiers": [],
            "merged_rule_overrides": None,
            "boundaries": [
                {
                    "function": "test_fn",
                    "transition": "boundary_crossing",
                    "from_tier": 4,
                    "to_tier": 2,
                    "overlay_scope": "/tmp/test",
                    "overlay_path": "src/wardline.overlay.yaml",
                },
            ],
            "governance_signals": [],
            "overlays_discovered": [],
            "scanner_config": None,
            "metadata": {},
        }), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--resolved", str(resolved),
            "--allow-registry-mismatch",
            "--allow-stale-resolved",
        ])
        # Should produce valid SARIF — the resolved boundaries are loaded
        sarif = json.loads(result.stdout)
        assert isinstance(sarif, dict)
        assert "runs" in sarif

    def test_stale_resolved_blocks_by_default(self, tmp_path: Path) -> None:
        """Hash mismatch without --allow-stale-resolved must exit 2."""
        manifest = _minimal_manifest(tmp_path)

        resolved = tmp_path / "wardline.resolved.json"
        resolved.write_text(json.dumps({
            "format_version": "0.2",
            "resolved_at": "2026-01-01T00:00:00Z",
            "root": ".",
            "manifest_source": "wardline.yaml",
            "manifest_hash": "sha256:wrong",
            "tiers": [],
            "module_tiers": [],
            "boundaries": [],
            "governance_signals": [],
            "overlays_discovered": [],
            "scanner_config": None,
            "metadata": {},
        }), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--resolved", str(resolved),
        ])
        assert result.exit_code == 2
        assert "stale" in result.output or "stale" in (result.stderr or "")

    def test_resolved_rejects_skip_promotion(self, tmp_path: Path) -> None:
        """Resolved file with T4→T1 skip-promotion must exit 2."""
        manifest = _minimal_manifest(tmp_path)

        resolved = tmp_path / "wardline.resolved.json"
        resolved.write_text(json.dumps({
            "format_version": "0.2",
            "manifest_hash": "sha256:wrong",
            "boundaries": [
                {
                    "function": "bad_fn",
                    "transition": "shape_validation",
                    "from_tier": 4,
                    "to_tier": 1,
                },
            ],
            "overlays_discovered": [],
        }), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--resolved", str(resolved),
            "--allow-stale-resolved",
        ])
        assert result.exit_code == 2
        assert "skip-promotion" in (result.output + (result.stderr or "")).lower()

    def test_resolved_rejects_duplicate_boundary(self, tmp_path: Path) -> None:
        """Resolved file with duplicate function boundaries must exit 2."""
        manifest = _minimal_manifest(tmp_path)

        resolved = tmp_path / "wardline.resolved.json"
        resolved.write_text(json.dumps({
            "format_version": "0.2",
            "manifest_hash": "sha256:wrong",
            "boundaries": [
                {"function": "dup_fn", "transition": "shape_validation",
                 "from_tier": 4, "to_tier": 3},
                {"function": "dup_fn", "transition": "semantic_validation",
                 "from_tier": 3, "to_tier": 2},
            ],
            "overlays_discovered": [],
        }), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--resolved", str(resolved),
            "--allow-stale-resolved",
        ])
        assert result.exit_code == 2
        assert "duplicate" in (result.output + (result.stderr or "")).lower()

    def test_resolved_rejects_uncovered_rule_override(self, tmp_path: Path) -> None:
        """Resolved file introducing rule overrides absent from base must exit 2."""
        manifest = _minimal_manifest(tmp_path)

        resolved = tmp_path / "wardline.resolved.json"
        resolved.write_text(json.dumps({
            "format_version": "0.2",
            "manifest_hash": "sha256:wrong",
            "boundaries": [],
            "merged_rule_overrides": [
                {"id": "PY-WL-001", "severity": "OFF"},
            ],
            "overlays_discovered": [],
        }), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--resolved", str(resolved),
            "--allow-stale-resolved",
        ])
        assert result.exit_code == 2
        assert "absent from base" in (result.output + (result.stderr or "")).lower()


@pytest.mark.integration
class TestSarifRunLevelProperties:
    """Gap 3: SARIF run-level identity properties (§10.1)."""

    def test_sarif_output_contains_input_hash(self, tmp_path: Path) -> None:
        """wardline.inputHash present and starts with sha256:."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.inputHash" in props
        assert props["wardline.inputHash"].startswith("sha256:")

    def test_sarif_output_contains_input_files(self, tmp_path: Path) -> None:
        """wardline.inputFiles matches scanned file count."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.inputFiles" in props
        assert props["wardline.inputFiles"] == 1

    def test_sarif_output_overlay_hashes_present(self, tmp_path: Path) -> None:
        """wardline.overlayHashes is a list (empty when no overlays)."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.overlayHashes" in props
        assert isinstance(props["wardline.overlayHashes"], list)

    def test_sarif_input_hash_deterministic(self, tmp_path: Path) -> None:
        """Two identical runs produce same inputHash."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        args = [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--verification-mode",
        ]
        r1 = runner.invoke(cli, args)
        r2 = runner.invoke(cli, args)
        sarif1 = json.loads(r1.stdout)
        sarif2 = json.loads(r2.stdout)
        assert (
            sarif1["runs"][0]["properties"]["wardline.inputHash"]
            == sarif2["runs"][0]["properties"]["wardline.inputHash"]
        )

    def test_sarif_property_bag_version_is_0_3(self, tmp_path: Path) -> None:
        """Property bag version is 0.3 after Gap 3."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "0.5"

    def test_input_hash_failure_exits_tool_error(self, tmp_path: Path) -> None:
        """inputHash OSError produces TOOL_ERROR finding AND exit code 1."""
        from unittest.mock import patch

        from wardline.scanner.engine import ScanResult

        manifest = _minimal_manifest(tmp_path)
        # Fake a scan result with a file path that no longer exists
        ghost = tmp_path / "ghost.py"
        fake_result = ScanResult(
            findings=[],
            files_scanned=1,
            scanned_file_paths=[ghost],  # does not exist on disk
        )

        with patch(
            "wardline.scanner.engine.ScanEngine.scan",
            return_value=fake_result,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, [
                "scan", str(tmp_path),
                "--manifest", str(manifest),
                "--allow-registry-mismatch",
            ])

        assert result.exit_code == 1
        sarif = json.loads(result.stdout)
        tool_errors = [
            r for r in sarif["runs"][0]["results"]
            if r["ruleId"] == "TOOL-ERROR"
        ]
        assert len(tool_errors) == 1
