"""End-to-end CLI tests: default scan artifact anchoring to the weft-project root.

Covers the behaviour introduced by Tasks 1-3 of the weft-seam-conformance program:
``wardline scan <subdir>`` must write its artifact at ``<project-root>/.wardline/``,
not under the scanned subdirectory.

Harness pattern: ``CliRunner().invoke(cli, ["scan", str(path)])`` — same as
``tests/unit/cli/test_cli.py``; no custom fixtures needed.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.mcp.server import _scan as mcp_scan

_STAMPED_JSONL_RE = re.compile(r"^\d{8}T\d{6}Z(-\d{3})?-findings\.jsonl$")


def _scan_artifacts_jsonl(project: Path) -> list[Path]:
    return sorted((project / ".wardline").glob("*-findings.jsonl"))


def _only_scan_artifact(project: Path) -> Path:
    paths = _scan_artifacts_jsonl(project)
    assert len(paths) == 1, f"expected exactly 1 artifact, got {paths}"
    return paths[0]


# ---------------------------------------------------------------------------
# Test 1: subdir scan writes artifact at <project-root>/.wardline/, NOT under sub
# ---------------------------------------------------------------------------

def test_cli_subdir_scan_writes_artifact_at_project_root(tmp_path: Path) -> None:
    """``wardline scan src/pkg`` (weft project at tmp_path) → artifact at
    ``tmp_path/.wardline/``, NOT at ``tmp_path/src/pkg/.wardline/``."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    (sub / "m.py").write_text("x = 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(sub)])

    assert result.exit_code == 0, result.output
    # Positive: artifact appeared at project root
    artifacts_dir = tmp_path / ".wardline"
    assert artifacts_dir.exists(), "expected .wardline/ at project root"
    jsonl_files = list(artifacts_dir.glob("*-findings.jsonl"))
    assert any(_STAMPED_JSONL_RE.match(p.name) for p in jsonl_files), (
        f"no timestamped findings artifact in {artifacts_dir!s}: {[p.name for p in jsonl_files]}"
    )
    # Negative: NO artifact written under the scanned subdirectory
    assert not (sub / ".wardline").exists(), (
        "artifact was written under the subdir — anchoring is broken"
    )


# ---------------------------------------------------------------------------
# Test 2: true-root scan writes artifact at <root>/.wardline/
# ---------------------------------------------------------------------------

def test_cli_true_root_scan_writes_artifact_at_root(tmp_path: Path) -> None:
    """``wardline scan <root>`` where root carries ``weft.toml`` → artifact at
    ``<root>/.wardline/``."""
    (tmp_path / "weft.toml").write_text('[wardline]\nsource_roots = ["."]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact = _only_scan_artifact(tmp_path)
    assert artifact.parent == tmp_path / ".wardline"
    assert _STAMPED_JSONL_RE.match(artifact.name)
    assert str(artifact) in result.output


# ---------------------------------------------------------------------------
# Test 3: unfederated tree (no weft.toml up the chain) → fallback to <scan-path>/.wardline/
# ---------------------------------------------------------------------------

def test_cli_unfederated_tree_falls_back_to_scan_path(tmp_path: Path) -> None:
    """No ``weft.toml`` anywhere in the ancestry → ``project_root_for`` returns
    ``scan_path`` itself, so the artifact lands at ``<scan_path>/.wardline/``."""
    # tmp_path is deeply nested under /tmp — well outside any weft project root.
    # Do NOT create a weft.toml.
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact = _only_scan_artifact(tmp_path)
    assert artifact.parent == tmp_path / ".wardline"
    assert _STAMPED_JSONL_RE.match(artifact.name)


# ---------------------------------------------------------------------------
# Test 4: custom artifacts.dir anchors to <project-root>/out/wl
# ---------------------------------------------------------------------------

def test_cli_custom_artifacts_dir_anchors_to_project_root(tmp_path: Path) -> None:
    """``[wardline.artifacts] dir = "out/wl"`` in weft.toml (root scan) → artifact at
    ``<project-root>/out/wl/``, NOT at ``<project-root>/.wardline/``.

    Subdir scans don't load the project root's config (by design — the docstring and
    task 3 message both say subdir scans don't load project policy). Root scans do.
    """
    (tmp_path / "weft.toml").write_text(
        '[wardline]\nsource_roots = ["."]\n\n[wardline.artifacts]\ndir = "out/wl"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    artifact_dir = tmp_path / "out" / "wl"
    assert artifact_dir.exists(), f"expected artifact dir at {artifact_dir}"
    jsonl_files = sorted(artifact_dir.glob("*-findings.jsonl"))
    assert jsonl_files, f"no artifacts in {artifact_dir}"
    assert _STAMPED_JSONL_RE.match(jsonl_files[0].name)
    # No default .wardline at project root (custom dir takes over)
    assert not (tmp_path / ".wardline").exists()


# ---------------------------------------------------------------------------
# Test 5: explicit --output is unaffected (verbatim) and no .wardline/ is created
# ---------------------------------------------------------------------------

def test_cli_explicit_output_unaffected(tmp_path: Path) -> None:
    """``--output path/to/findings.jsonl`` writes exactly there and NEVER creates a
    ``.wardline/`` directory under the project root."""
    (tmp_path / "weft.toml").write_text('[wardline]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    out_dir = tmp_path / "ci"
    out_dir.mkdir()
    out = out_dir / "findings.jsonl"

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists(), f"expected output at {out}"
    # No automatic .wardline/ when --output is explicit
    assert not (tmp_path / ".wardline").exists(), (
        ".wardline/ was created even though --output was explicit"
    )


# ---------------------------------------------------------------------------
# Test 6: MCP _scan() writes NO disk artifact (regression guard)
# ---------------------------------------------------------------------------

def test_mcp_scan_writes_no_disk_artifact(tmp_path: Path) -> None:
    """The MCP ``scan`` tool must NEVER write a ``.wardline/`` disk artifact.

    The MCP surface returns findings in-band over JSON-RPC; disk writes are the
    CLI's job.  This is a regression guard: any change that wires write_scan_artifact
    into the MCP path would be caught here."""
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    result = mcp_scan(args={}, root=tmp_path)

    # Sanity check: scan actually ran and returned a result dict
    assert isinstance(result, dict), f"expected dict result, got {type(result)}"
    # No .wardline/ may exist after an MCP scan
    assert not (tmp_path / ".wardline").exists(), (
        "MCP _scan() created a .wardline/ directory — disk writes must be CLI-only"
    )
