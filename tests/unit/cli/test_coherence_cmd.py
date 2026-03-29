"""Tests for wardline manifest coherence command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.coherence_cmd import coherence

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "governance"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ── Helpers ────────────────────────────────────────────────────────


def _invoke(
    runner: CliRunner,
    *extra_args: str,
    manifest: str | None = None,
    path: str | None = None,
):
    """Invoke coherence with default fixture paths unless overridden."""
    args = [
        "--manifest", manifest or str(FIXTURES / "wardline.yaml"),
        "--path", path or str(FIXTURES / "src"),
        *extra_args,
    ]
    return runner.invoke(coherence, args, catch_exceptions=True)


def _write_minimal_manifest(
    tmp_path: Path,
    *,
    taint: str = "ASSURED",
    with_overlay: bool = False,
    overlay_function: str = "do_thing",
    tier_ids: list[tuple[str, int]] | None = None,
    governance_profile: str = "lite",
) -> Path:
    """Write a minimal valid wardline.yaml and return its path.

    tier_ids: list of (id, tier_number) pairs. Defaults to two generic tiers.
    The tier IDs are independent of default_taint (which is a TaintState enum
    per schema). The coherence checks only detect downgrades when the
    default_taint value happens to match a tier ID in both baseline and
    current manifest.
    """
    if tier_ids is None:
        tier_ids = [("ASSURED", 1), ("EXTERNAL_RAW", 4)]

    manifest_yaml = tmp_path / "wardline.yaml"
    tiers_block = "\n".join(
        f'  - id: "{tid}"\n    tier: {tnum}\n    description: "{tid}"'
        for tid, tnum in tier_ids
    )
    manifest_yaml.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        "  organisation: test\n"
        f'governance_profile: "{governance_profile}"\n'
        "tiers:\n"
        f"{tiers_block}\n"
        "module_tiers:\n"
        '  - path: "src/"\n'
        f'    default_taint: "{taint}"\n'
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides: []\n"
    )
    if with_overlay:
        overlay_dir = tmp_path / "overlays" / "src"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "wardline.overlay.yaml").write_text(
            '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
            'overlay_for: "src/"\n'
            "boundaries:\n"
            f'  - function: "{overlay_function}"\n'
            '    transition: "ingest"\n'
        )
    return manifest_yaml


def _write_tier_downgrade_fixture(tmp_path: Path) -> Path:
    """Write a manifest + baseline that triggers tier_downgrade.

    The trick: tier IDs must match the TaintState values used as
    default_taint, because check_tier_downgrades looks up default_taint
    in `{t.id: t.tier for t in tiers}`.

    Baseline: src/ had default_taint="ASSURED", tier map ASSURED->1.
    Current:  src/ has default_taint="EXTERNAL_RAW", tier map EXTERNAL_RAW->4.
    Downgrade: tier 1 -> tier 4.
    """
    manifest_yaml = _write_minimal_manifest(
        tmp_path,
        taint="EXTERNAL_RAW",
        tier_ids=[("ASSURED", 1), ("EXTERNAL_RAW", 4)],
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


class TestCoherenceClean:
    """test_coherence_clean — fixture with no issues -> exit 0."""

    def test_coherence_clean(self, runner: CliRunner, tmp_path: Path) -> None:
        """A minimal project with no issues produces 0 issues."""
        manifest_yaml = _write_minimal_manifest(tmp_path)
        # Source with no wardline decorators -> no orphans, no undeclared
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("def plain_func(): ...\n")
        # Perimeter baseline present (avoids first_scan_perimeter warning)
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )

        result = _invoke(
            runner,
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0, f"stdout: {result.output}"
        assert "0 issues found" in result.output


class TestCoherenceWithErrors:
    """test_coherence_with_errors — fixture with tier downgrade -> shows ERROR."""

    def test_coherence_with_errors(self, runner: CliRunner, tmp_path: Path) -> None:
        """Tier downgrade produces an ERROR-level issue."""
        manifest_yaml = _write_tier_downgrade_fixture(tmp_path)
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "__init__.py").write_text("")

        result = _invoke(
            runner,
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert "[ERROR] tier_downgrade" in result.output


class TestCoherenceGateFailsOnError:
    """test_coherence_gate_fails_on_error — --gate + tier downgrade -> exit 1."""

    def test_coherence_gate_fails_on_error(self, runner: CliRunner, tmp_path: Path) -> None:
        manifest_yaml = _write_tier_downgrade_fixture(tmp_path)
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "__init__.py").write_text("")

        result = _invoke(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 1


class TestCoherenceGatePassesOnWarnings:
    """test_coherence_gate_passes_on_warnings — warnings only + --gate -> exit 0."""

    def test_coherence_gate_passes_on_warnings(self, runner: CliRunner, tmp_path: Path) -> None:
        """Warnings (orphaned annotation) without ERROR issues pass the gate."""
        manifest_yaml = _write_minimal_manifest(tmp_path)
        # Source with an annotated function but no overlay -> orphaned_annotation (WARNING)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text(
            "from wardline.decorators import external_boundary\n\n"
            "@external_boundary\n"
            "def orphan_func(): ...\n"
        )
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )

        result = _invoke(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0


class TestCoherenceJsonOutput:
    """test_coherence_json_output — --json -> valid JSON with correct fields."""

    def test_coherence_json_output(self, runner: CliRunner, tmp_path: Path) -> None:
        # Create a project that produces at least one issue
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text(
            "from wardline.decorators import external_boundary\n\n"
            "@external_boundary\n"
            "def orphan_func(): ...\n"
        )
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )

        result = _invoke(
            runner,
            "--json",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        record = data[0]
        assert "check_name" in record
        assert "severity" in record
        assert "file_path" in record
        assert "function" in record
        assert "message" in record
        assert "category" in record


class TestCoherenceJsonHasCategory:
    """test_coherence_json_has_category — JSON includes category field."""

    def test_coherence_json_has_category(self, runner: CliRunner, tmp_path: Path) -> None:
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text(
            "from wardline.decorators import external_boundary\n\n"
            "@external_boundary\n"
            "def orphan_func(): ...\n"
        )
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )

        result = _invoke(
            runner,
            "--json",
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        data = json.loads(result.output)
        assert isinstance(data, list)
        for record in data:
            assert record["category"] in ("policy", "enforcement")


class TestCoherenceMalformedManifest:
    """test_coherence_malformed_manifest — corrupt YAML -> exit 2."""

    def test_coherence_malformed_manifest(self, runner: CliRunner, tmp_path: Path) -> None:
        bad_manifest = tmp_path / "wardline.yaml"
        bad_manifest.write_text(": : : not valid yaml [[[")

        src_dir = tmp_path / "src"
        src_dir.mkdir()

        result = _invoke(
            runner,
            manifest=str(bad_manifest),
            path=str(src_dir),
        )
        assert result.exit_code == 2


class TestCoherenceAllChecksAggregate:
    """test_coherence_all_checks_aggregate — multiple check types -> correct summary."""

    def test_coherence_all_checks_aggregate(self, runner: CliRunner, tmp_path: Path) -> None:
        """A project triggering multiple check types shows correct summary counts."""
        # Trigger: orphaned_annotation (no overlay), and no perimeter baseline
        # -> first_scan_perimeter (WARNING).
        manifest_yaml = _write_minimal_manifest(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text(
            "from wardline.decorators import external_boundary, validates_shape\n\n"
            "@external_boundary\n"
            "def func_a(): ...\n\n"
            "@validates_shape\n"
            "def func_b(): ...\n"
        )
        # No perimeter baseline -> triggers first_scan_perimeter

        result = _invoke(
            runner,
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0
        assert "issues found" in result.output
        assert "error(s)" in result.output
        assert "warning(s)" in result.output
        # Should have at least 2 orphaned annotations + 1 first_scan_perimeter = 3+
        # Parse the count from "N issues found"
        import re
        m = re.search(r"(\d+) issues found", result.output)
        assert m is not None
        count = int(m.group(1))
        assert count >= 3, f"Expected >=3 issues, got {count}. Output: {result.output}"


class TestCoherenceRestorationEvidenceGate:
    """--gate + restoration overclaim -> exit 1 with insufficient_restoration_evidence."""

    def test_restoration_overclaim_gates(self, runner: CliRunner, tmp_path: Path) -> None:
        """Restoration boundary that overclaims tier (structural only → tier 1) fails gate."""
        manifest_yaml = _write_minimal_manifest(tmp_path)
        # Create overlay with a restoration boundary that overclaims
        overlay_dir = tmp_path / "src"
        overlay_dir.mkdir(exist_ok=True)
        (overlay_dir / "__init__.py").write_text("")
        (overlay_dir / "wardline.overlay.yaml").write_text(
            '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
            'overlay_for: "src/"\n'
            "boundaries:\n"
            '  - function: "do_restore"\n'
            '    transition: "restoration"\n'
            "    restored_tier: 1\n"
            "    provenance:\n"
            "      structural: true\n"
            "      semantic: false\n"
            "      integrity: null\n"
            "      institutional: null\n"
        )
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )

        result = _invoke(
            runner,
            "--gate",
            manifest=str(manifest_yaml),
            path=str(overlay_dir),
        )
        assert result.exit_code == 1, f"Expected exit 1, got {result.exit_code}. Output: {result.output}"
        assert "insufficient_restoration_evidence" in result.output


class TestAssuranceProfileAutoGate:
    """Assurance profile forces gating without --gate flag."""

    def test_assurance_profile_forces_gate(self, runner: CliRunner, tmp_path: Path) -> None:
        """Coherence failures with assurance profile exit non-zero even without --gate."""
        manifest_yaml = _write_minimal_manifest(
            tmp_path,
            taint="EXTERNAL_RAW",
            tier_ids=[("ASSURED", 1), ("EXTERNAL_RAW", 4)],
            governance_profile="assurance",
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
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "__init__.py").write_text("")

        # No --gate flag, but assurance profile should force it
        result = _invoke(
            runner,
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 1, (
            f"Expected exit 1 (assurance auto-gate), got {result.exit_code}. "
            f"Output: {result.output}"
        )

    def test_lite_profile_no_auto_gate(self, runner: CliRunner, tmp_path: Path) -> None:
        """Coherence failures with lite profile exit 0 without --gate."""
        manifest_yaml = _write_tier_downgrade_fixture(tmp_path)
        (tmp_path / "wardline.perimeter.baseline.json").write_text(
            '{"version":"1","module_paths":["src/"]}\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "__init__.py").write_text("")

        # No --gate flag, lite profile -> exit 0 even with errors
        result = _invoke(
            runner,
            manifest=str(manifest_yaml),
            path=str(src_dir),
        )
        assert result.exit_code == 0, (
            f"Expected exit 0 (lite no auto-gate), got {result.exit_code}. "
            f"Output: {result.output}"
        )
