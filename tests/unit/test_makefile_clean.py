from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAKE = shutil.which("make")


pytestmark = pytest.mark.skipif(MAKE is None, reason="make is not installed")


def run_make_clean(workdir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [MAKE, "-f", str(PROJECT_ROOT / "Makefile"), "clean"],
        cwd=workdir,
        check=False,
        text=True,
        capture_output=True,
    )


def test_make_clean_refuses_symlinked_recursive_targets(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    keep = outside / "keep.txt"
    keep.write_text("keep", encoding="utf-8")

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "dist").symlink_to(outside, target_is_directory=True)

    result = run_make_clean(workdir)

    assert result.returncode != 0
    assert "refusing to remove symlink dist" in result.stderr
    assert keep.read_text(encoding="utf-8") == "keep"
    assert (workdir / "dist").is_symlink()


def test_make_clean_removes_expected_non_symlink_artifacts(tmp_path: Path) -> None:
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    for dirname in (
        "dist",
        "build",
        "example.egg-info",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    ):
        artifact_dir = workdir / dirname
        artifact_dir.mkdir()
        (artifact_dir / "artifact.txt").write_text("artifact", encoding="utf-8")
    for filename in (".coverage", "coverage.json"):
        (workdir / filename).write_text("artifact", encoding="utf-8")
    pycache = workdir / "pkg" / "__pycache__"
    pycache.mkdir(parents=True)
    (pycache / "module.pyc").write_text("artifact", encoding="utf-8")

    result = run_make_clean(workdir)

    assert result.returncode == 0, result.stderr
    for name in (
        "dist",
        "build",
        "example.egg-info",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".coverage",
        "coverage.json",
    ):
        assert not (workdir / name).exists()
    assert not pycache.exists()
