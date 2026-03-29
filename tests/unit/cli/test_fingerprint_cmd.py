"""Tests for wardline fingerprint update / diff commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.fingerprint_cmd import diff, update

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "governance"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ── Helpers ────────────────────────────────────────────────────────


def _write_manifest(tmp_path: Path) -> Path:
    """Write a minimal valid wardline.yaml and return its path."""
    manifest_path = tmp_path / "wardline.yaml"
    manifest_path.write_text(
        '$id: "https://wardline.dev/schemas/1.0/wardline"\n'
        "metadata:\n"
        "  organisation: test\n"
        "tiers:\n"
        '  - id: "ASSURED"\n'
        "    tier: 1\n"
        '    description: "tier 1"\n'
        '  - id: "EXTERNAL_RAW"\n'
        "    tier: 4\n"
        '    description: "tier 4"\n'
        "module_tiers:\n"
        '  - path: "src/"\n'
        '    default_taint: "ASSURED"\n'
        "delegation:\n"
        '  default_authority: "RELAXED"\n'
        "rules:\n"
        "  overrides: []\n"
    )
    return manifest_path


def _write_source(tmp_path: Path, *, with_functions: bool = True) -> Path:
    """Write a source file with wardline-decorated functions."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    example = src_dir / "example.py"
    if with_functions:
        example.write_text(
            "from wardline.decorators import external_boundary, validates_shape, integral_read\n\n"
            "@external_boundary\n"
            "def fetch_data(url: str) -> dict:\n"
            "    return {}\n\n"
            "@validates_shape\n"
            "def check_schema(data: dict) -> bool:\n"
            "    return True\n\n"
            "@integral_read\n"
            "def get_config() -> dict:\n"
            "    return {}\n"
        )
    else:
        example.write_text("def plain_function(): pass\n")
    return src_dir


def _write_baseline(
    tmp_path: Path,
    fingerprints: list[dict],
    *,
    python_version: str | None = None,
    coverage: dict | None = None,
) -> Path:
    """Write a fingerprint baseline JSON."""
    py_ver = python_version or f"{sys.version_info.major}.{sys.version_info.minor}"
    baseline = {
        "$id": "https://wardline.dev/schemas/1.0/fingerprint.schema.json",
        "python_version": py_ver,
        "generated_at": "2026-03-22T00:00:00+00:00",
        "coverage": coverage or {
            "annotated": len(fingerprints),
            "total": len(fingerprints),
            "ratio": 1.0 if fingerprints else 0.0,
            "tier1_annotated": 0,
            "tier1_total": 0,
        },
        "fingerprints": fingerprints,
    }
    path = tmp_path / "wardline.fingerprint.json"
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    return path


def _compute_real_hashes(src_dir: Path) -> dict[str, str]:
    """Compute actual annotation hashes for the source files."""
    import ast

    from wardline.scanner.discovery import discover_annotations
    from wardline.scanner.fingerprint import compute_annotation_fingerprint

    hashes: dict[str, str] = {}
    for py_file in sorted(src_dir.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
        anns = discover_annotations(tree, str(py_file))
        for (_fp, qn), ann_list in anns.items():
            dec_names = [a.canonical_name for a in ann_list]
            h = compute_annotation_fingerprint(qn, dec_names, {})
            hashes[qn] = h
    return hashes


# ── Test: fingerprint update ──────────────────────────────────────


def test_fingerprint_update_creates_baseline(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Update writes a valid wardline.fingerprint.json."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    result = runner.invoke(
        update,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    baseline_path = tmp_path / "wardline.fingerprint.json"
    assert baseline_path.exists()

    data = json.loads(baseline_path.read_text())
    assert "fingerprints" in data
    assert len(data["fingerprints"]) == 3
    assert data["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert "$id" in data

    # All entries should have required fields
    for entry in data["fingerprints"]:
        assert "qualified_name" in entry
        assert "annotation_hash" in entry
        assert "artefact_class" in entry
        assert "last_changed" in entry


def test_fingerprint_update_empty_project(
    runner: CliRunner, tmp_path: Path
) -> None:
    """No annotated functions -> empty entries, 0/N coverage."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path, with_functions=False)

    result = runner.invoke(
        update,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "wardline.fingerprint.json").read_text())
    assert data["fingerprints"] == []
    assert data["coverage"]["annotated"] == 0
    assert data["coverage"]["total"] >= 1  # plain_function counts
    assert "0/" in result.output or "coverage" in result.output


def test_fingerprint_update_includes_coverage(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Coverage section has correct counts."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    result = runner.invoke(
        update,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0
    data = json.loads((tmp_path / "wardline.fingerprint.json").read_text())
    cov = data["coverage"]
    assert cov["annotated"] == 3
    assert cov["total"] == 3
    assert cov["ratio"] == 1.0
    assert "coverage" in result.output


# ── Test: fingerprint diff ────────────────────────────────────────


def test_fingerprint_diff_no_changes(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Baseline matches current -> 0 changes."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    # First, generate the baseline via update
    runner.invoke(
        update,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    # Then diff
    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "0 changes" in result.output


def test_fingerprint_diff_detects_added(
    runner: CliRunner, tmp_path: Path
) -> None:
    """New function in current -> ADDED."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    # Write baseline with only 2 of the 3 functions
    real_hashes = _compute_real_hashes(src_dir)
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "ADDED" in result.output
    assert "get_config" in result.output


def test_fingerprint_diff_detects_removed(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Function in baseline but not current -> REMOVED."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Write baseline with an extra function that doesn't exist in code
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "deleted_function",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "deadbeefdeadbeef",
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "REMOVED" in result.output
    assert "deleted_function" in result.output


def test_fingerprint_diff_detects_modified(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Decorator changed -> MODIFIED."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Write baseline with a different hash for one function
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "MODIFIED" in result.output
    assert "fetch_data" in result.output


def test_fingerprint_diff_json_output(
    runner: CliRunner, tmp_path: Path
) -> None:
    """--json -> valid JSON with categories."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    # Generate baseline, then add a change
    runner.invoke(
        update,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    # Modify source to add a new annotated function
    example = src_dir / "example.py"
    example.write_text(
        example.read_text()
        + "\n@validates_shape\ndef new_function(x): return True\n"
    )

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--json"],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "added" in data
    assert "removed" in data
    assert "modified" in data
    assert "total_changes" in data
    assert "coverage" in data
    assert data["total_changes"] >= 1


def test_fingerprint_diff_gate_on_tier1_removal(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Removed in tier 1 + --gate -> exit 1."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Baseline with a tier 1 function that no longer exists
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "deleted_tier1_func",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "deadbeefdeadbeef",
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--gate"],
        catch_exceptions=True,
    )

    assert result.exit_code == 1


def test_fingerprint_diff_gate_passes_on_tier2_removal(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Removed in tier 2 + --gate -> exit 0."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Baseline with a tier 4 function that no longer exists
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "deleted_tier4_func",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": "deadbeefdeadbeef",
            "tier_context": 4,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "enforcement",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--gate"],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output


def test_fingerprint_diff_gate_passes_on_modification(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Modified in tier 1 + --gate -> exit 0 (gate only on removal)."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Baseline with a wrong hash for a tier 1 function (MODIFIED, not REMOVED)
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "cafebabecafebabecafebabecafebabe",
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--gate"],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output


def test_fingerprint_diff_python_version_mismatch(
    runner: CliRunner, tmp_path: Path
) -> None:
    """major.minor differs -> all MODIFIED with message; --gate does NOT exit 1."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Write baseline with a different Python version (major.minor)
    _write_baseline(
        tmp_path,
        [
            {
                "qualified_name": "fetch_data",
                "module": str(src_dir / "example.py"),
                "decorators": ["external_boundary"],
                "annotation_hash": real_hashes["fetch_data"],
                "tier_context": 1,
                "boundary_transition": "ingress",
                "last_changed": "2026-03-01",
                "artefact_class": "policy",
            },
            {
                "qualified_name": "check_schema",
                "module": str(src_dir / "example.py"),
                "decorators": ["validates_shape"],
                "annotation_hash": real_hashes["check_schema"],
                "tier_context": 1,
                "boundary_transition": "shape_validation",
                "last_changed": "2026-03-01",
                "artefact_class": "policy",
            },
            {
                "qualified_name": "get_config",
                "module": str(src_dir / "example.py"),
                "decorators": ["integral_read"],
                "annotation_hash": real_hashes["get_config"],
                "tier_context": 1,
                "boundary_transition": None,
                "last_changed": "2026-03-01",
                "artefact_class": "policy",
            },
        ],
        python_version="3.99",
    )

    # Without gate
    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "version mismatch" in result.output.lower()
    assert "MODIFIED" in result.output

    # With gate: version mismatch marks as MODIFIED (not REMOVED), so gate passes
    result_gate = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--gate"],
        catch_exceptions=True,
    )

    assert result_gate.exit_code == 0, result_gate.output


def test_fingerprint_diff_malformed_baseline(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Corrupt JSON -> exit 2."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    # Write malformed JSON as baseline
    baseline_path = tmp_path / "wardline.fingerprint.json"
    baseline_path.write_text("{{{not valid json", encoding="utf-8")

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    assert result.exit_code == 2


# ── Test: --since filter ─────────────────────────────────────────


def test_fingerprint_diff_since_filters_old_changes(
    runner: CliRunner, tmp_path: Path
) -> None:
    """--since excludes changes with last_changed before the cutoff."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Baseline: one function has old hash (MODIFIED), one extra (REMOVED)
    # Use different last_changed dates so we can filter
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": "deadbeefdeadbeef",  # wrong hash -> MODIFIED
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-01-15",  # old
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": "deadbeefdeadbeef",  # wrong hash -> MODIFIED
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-20",  # recent
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "old_removed",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "aabbccddaabbccdd",
            "tier_context": 4,
            "boundary_transition": None,
            "last_changed": "2026-01-10",  # old
            "artefact_class": "enforcement",
        },
        {
            "qualified_name": "recent_removed",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "eeff0011eeff0011",
            "tier_context": 4,
            "boundary_transition": None,
            "last_changed": "2026-03-25",  # recent
            "artefact_class": "enforcement",
        },
    ])

    result = runner.invoke(
        diff,
        [
            "--manifest", str(manifest_path),
            "--path", str(src_dir),
            "--json",
            "--since", "2026-03-01",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    # Both MODIFIED entries use current last_changed (today), which is >= 2026-03-01
    # so both remain. The key filtering is on REMOVED entries.
    removed_names = [e["qualified_name"] for e in data["removed"]]
    # old_removed (2026-01-10) filtered out, recent_removed (2026-03-25) kept
    assert "recent_removed" in removed_names
    assert "old_removed" not in removed_names

    # total_changes reflects filtered count
    assert data["total_changes"] == len(data["added"]) + len(data["removed"]) + len(data["modified"])


def test_fingerprint_diff_since_no_filter_without_flag(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Without --since, all changes appear regardless of date."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": "deadbeefdeadbeef",  # MODIFIED
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2025-01-01",  # very old
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2025-01-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2025-01-01",
            "artefact_class": "policy",
        },
    ])

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir), "--json"],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    # fetch_data should still appear as MODIFIED even with old date
    modified_names = [e["qualified_name"] for e in data["modified"]]
    assert "fetch_data" in modified_names


def test_fingerprint_diff_since_filters_null_last_changed(
    runner: CliRunner, tmp_path: Path
) -> None:
    """--since drops removed entries with null last_changed."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Baseline has two extra functions that don't exist in code (REMOVED).
    # One has null last_changed, the other has a recent date.
    _write_baseline(tmp_path, [
        {
            "qualified_name": "fetch_data",
            "module": str(src_dir / "example.py"),
            "decorators": ["external_boundary"],
            "annotation_hash": real_hashes["fetch_data"],
            "tier_context": 1,
            "boundary_transition": "ingress",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "check_schema",
            "module": str(src_dir / "example.py"),
            "decorators": ["validates_shape"],
            "annotation_hash": real_hashes["check_schema"],
            "tier_context": 1,
            "boundary_transition": "shape_validation",
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "get_config",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": real_hashes["get_config"],
            "tier_context": 1,
            "boundary_transition": None,
            "last_changed": "2026-03-01",
            "artefact_class": "policy",
        },
        {
            "qualified_name": "removed_no_date",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "aabbccddaabbccdd",
            "tier_context": 4,
            "boundary_transition": None,
            "last_changed": None,  # no date -> filtered out
            "artefact_class": "enforcement",
        },
        {
            "qualified_name": "removed_with_date",
            "module": str(src_dir / "example.py"),
            "decorators": ["integral_read"],
            "annotation_hash": "eeff0011eeff0011",
            "tier_context": 4,
            "boundary_transition": None,
            "last_changed": "2026-03-20",  # recent -> kept
            "artefact_class": "enforcement",
        },
    ])

    result = runner.invoke(
        diff,
        [
            "--manifest", str(manifest_path),
            "--path", str(src_dir),
            "--json",
            "--since", "2026-03-01",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    removed_names = [e["qualified_name"] for e in data["removed"]]
    # null last_changed -> filtered out by --since
    assert "removed_no_date" not in removed_names
    # recent date -> kept
    assert "removed_with_date" in removed_names


def test_fingerprint_diff_old_baseline_missing_fields(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Baseline lacks artefact_class -> graceful defaults."""
    manifest_path = _write_manifest(tmp_path)
    src_dir = _write_source(tmp_path)

    real_hashes = _compute_real_hashes(src_dir)
    # Write an old-format baseline with "entries" key and missing fields
    old_baseline = {
        "schema_version": "1.0",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "generated_at": "2026-03-22T00:00:00+00:00",
        "coverage": {
            "annotated": 3,
            "total": 3,
            "ratio": 1.0,
            "tier1_annotated": 1,
            "tier1_total": 1,
        },
        "entries": [
            {
                "qualified_name": "fetch_data",
                "module": str(src_dir / "example.py"),
                "decorators": ["external_boundary"],
                "annotation_hash": real_hashes["fetch_data"],
                "tier_context": 1,
                "boundary_transition": "ingress",
            },
            {
                "qualified_name": "check_schema",
                "module": str(src_dir / "example.py"),
                "decorators": ["validates_shape"],
                "annotation_hash": real_hashes["check_schema"],
                "tier_context": 1,
                "boundary_transition": "shape_validation",
            },
            {
                "qualified_name": "get_config",
                "module": str(src_dir / "example.py"),
                "decorators": ["integral_read"],
                "annotation_hash": real_hashes["get_config"],
                "tier_context": 1,
                "boundary_transition": None,
            },
        ],
    }

    baseline_path = tmp_path / "wardline.fingerprint.json"
    baseline_path.write_text(
        json.dumps(old_baseline, indent=2) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        diff,
        ["--manifest", str(manifest_path), "--path", str(src_dir)],
        catch_exceptions=True,
    )

    # Should succeed — backward compat handles missing fields
    assert result.exit_code == 0, result.output
    assert "0 changes" in result.output
