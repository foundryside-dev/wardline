"""Tests for scan artifact path anchoring and retention."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from wardline.core import artifacts
from wardline.core.config import ArtifactSettings, WardlineConfig


def _project(tmp_path: Path) -> None:
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")


def test_subdir_scan_anchors_artifact_to_project_root(tmp_path: Path) -> None:
    _project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    out = artifacts.write_scan_artifact(sub, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")
    assert out.read_text(encoding="utf-8") == "{}\n"


def test_root_scan_unchanged(tmp_path: Path) -> None:
    _project(tmp_path)
    out = artifacts.write_scan_artifact(tmp_path, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")


def test_unfederated_scan_writes_at_scan_path(tmp_path: Path) -> None:
    sub = tmp_path / "loose"
    sub.mkdir()
    out = artifacts.write_scan_artifact(sub, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (sub.resolve() / ".wardline")


def test_escaping_artifacts_dir_falls_back_under_project_root(tmp_path: Path) -> None:
    _project(tmp_path)
    cfg = WardlineConfig(artifacts=ArtifactSettings(dir="../../etc"))
    out = artifacts.write_scan_artifact(tmp_path, "jsonl", cfg, "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")


# --- Existing retention / collision tests ---

def test_retention_prunes_oldest(tmp_path: Path) -> None:
    """prune_scan_artifacts removes the oldest artifact when retain=2 and 2 exist."""
    _project(tmp_path)
    artifact_dir = tmp_path / ".wardline"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Create two "old" artifacts manually.
    old1 = artifact_dir / "20240101T000000Z-findings.jsonl"
    old2 = artifact_dir / "20240101T000001Z-findings.jsonl"
    old1.write_text("old1\n", encoding="utf-8")
    old2.write_text("old2\n", encoding="utf-8")

    # Write a new artifact — with retain=2 the oldest should be pruned.
    cfg = WardlineConfig(artifacts=ArtifactSettings(retain=2))
    out = artifacts.write_scan_artifact(tmp_path, "jsonl", cfg, "new\n")

    remaining = sorted(artifact_dir.iterdir(), key=lambda p: p.name)
    names = [p.name for p in remaining]
    assert out.name in names
    # Exactly one of the two old files should survive (the newer one).
    assert old2.name in names
    assert old1.name not in names


def test_collision_handled(tmp_path: Path) -> None:
    """write_scan_artifact allocates a unique name if the first candidate exists."""
    _project(tmp_path)
    artifact_dir = tmp_path / ".wardline"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Occupy a large number of candidates for the current second.
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (artifact_dir / f"{stamp}-findings.jsonl").write_text("occupied\n", encoding="utf-8")
    for i in range(1, 5):
        (artifact_dir / f"{stamp}-{i:03d}-findings.jsonl").write_text(f"occupied-{i}\n", encoding="utf-8")

    out = artifacts.write_scan_artifact(tmp_path, "jsonl", WardlineConfig(), "new\n")
    assert out.exists()
    assert out.read_text(encoding="utf-8") == "new\n"
