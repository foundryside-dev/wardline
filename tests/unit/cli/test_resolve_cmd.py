"""Tests for wardline resolve command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.resolve_cmd import resolve

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "governance"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ── Helpers ────────────────────────────────────────────────────────


def _write_minimal_manifest(tmp_path: Path) -> Path:
    """Write a minimal valid wardline.yaml with no overlays."""
    manifest = tmp_path / "wardline.yaml"
    manifest.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        '  organisation: "test"\n'
        "tiers:\n"
        '  - id: "ASSURED"\n'
        "    tier: 2\n"
        '    description: "Pipeline"\n'
        "module_tiers: []\n"
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides: []\n",
        encoding="utf-8",
    )
    return manifest


def _write_manifest_with_overlay(tmp_path: Path) -> Path:
    """Write manifest + overlay under tmp_path."""
    manifest = tmp_path / "wardline.yaml"
    manifest.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        '  organisation: "test"\n'
        "tiers:\n"
        '  - id: "ASSURED"\n'
        "    tier: 2\n"
        '    description: "Pipeline"\n'
        '  - id: "EXTERNAL_RAW"\n'
        "    tier: 4\n"
        '    description: "External"\n'
        "module_tiers:\n"
        '  - path: "src/"\n'
        '    default_taint: "EXTERNAL_RAW"\n'
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides:\n"
        '    - id: "PY-WL-001"\n'
        '      severity: "WARNING"\n',
        encoding="utf-8",
    )

    # Create overlay
    overlay_dir = tmp_path / "src"
    overlay_dir.mkdir(parents=True, exist_ok=True)
    overlay_file = overlay_dir / "wardline.overlay.yaml"
    overlay_file.write_text(
        '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
        'overlay_for: "src/"\n'
        "boundaries:\n"
        '  - function: "validate_input"\n'
        '    transition: "shape_validation"\n'
        "    from_tier: 4\n"
        "    to_tier: 2\n"
        "rule_overrides:\n"
        '  - id: "PY-WL-001"\n'
        '    severity: "ERROR"\n',
        encoding="utf-8",
    )
    return manifest


# ── Tests ──────────────────────────────────────────────────────────


def test_resolve_empty_project(runner: CliRunner, tmp_path: Path) -> None:
    """Empty project (no overlays) produces valid JSON with zero boundaries."""
    manifest = _write_minimal_manifest(tmp_path)
    result = runner.invoke(resolve, [
        "--manifest", str(manifest),
        "--path", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["format_version"] == "0.2"
    assert data["boundaries"] == []
    assert data["overlays_discovered"] == []
    assert data["manifest_hash"].startswith("sha256:")


def test_resolve_with_overlays(runner: CliRunner, tmp_path: Path) -> None:
    """Project with overlays produces boundaries with overlay_path and overlay_scope."""
    manifest = _write_manifest_with_overlay(tmp_path)
    result = runner.invoke(resolve, [
        "--manifest", str(manifest),
        "--path", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    assert len(data["boundaries"]) == 1
    boundary = data["boundaries"][0]
    assert boundary["overlay_path"] == "src/wardline.overlay.yaml"
    assert boundary["overlay_scope"] != ""
    assert boundary["function"] == "validate_input"

    assert len(data["overlays_discovered"]) == 1
    assert data["overlays_discovered"][0]["path"] == "src/wardline.overlay.yaml"


def test_resolve_output_flag(runner: CliRunner, tmp_path: Path) -> None:
    """--output writes to file instead of stdout."""
    manifest = _write_minimal_manifest(tmp_path)
    out_file = tmp_path / "resolved.json"
    result = runner.invoke(resolve, [
        "--manifest", str(manifest),
        "--path", str(tmp_path),
        "-o", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["format_version"] == "0.2"


def test_merged_overrides_have_source(runner: CliRunner, tmp_path: Path) -> None:
    """Merged overrides carry source field for provenance tracking."""
    manifest = _write_manifest_with_overlay(tmp_path)
    result = runner.invoke(resolve, [
        "--manifest", str(manifest),
        "--path", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    overrides = data["merged_rule_overrides"]
    assert len(overrides) >= 1
    # The PY-WL-001 override should have overlay source (overlay wins)
    pw001 = [o for o in overrides if o["id"] == "PY-WL-001"]
    assert len(pw001) == 1
    assert pw001[0]["source"] == "overlay:src/"


def test_resolve_metadata_included(runner: CliRunner, tmp_path: Path) -> None:
    """Resolved JSON includes metadata from root manifest."""
    manifest = _write_minimal_manifest(tmp_path)
    result = runner.invoke(resolve, [
        "--manifest", str(manifest),
        "--path", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["metadata"]["organisation"] == "test"
