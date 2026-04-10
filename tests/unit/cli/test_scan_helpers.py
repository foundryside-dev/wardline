"""Tests for SARIF run-level property computation helpers in cli/scan.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


class TestComputeManifestHash:
    def test_manifest_hash_is_root_only(self, tmp_path: Path) -> None:
        """manifestHash is SHA-256 of root manifest raw bytes only (§10.1)."""
        from wardline.cli.scan import _compute_manifest_hash

        manifest = tmp_path / "wardline.yaml"
        content = b"tiers: []\nmodule_tiers: []\n"
        manifest.write_bytes(content)

        result = _compute_manifest_hash(manifest)
        expected = "sha256:" + hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_manifest_hash_unchanged_by_overlay_changes(self, tmp_path: Path) -> None:
        """Adding overlays must not change manifestHash."""
        from wardline.cli.scan import _compute_manifest_hash

        manifest = tmp_path / "wardline.yaml"
        content = b"tiers: []\nmodule_tiers: []\n"
        manifest.write_bytes(content)

        hash_before = _compute_manifest_hash(manifest)

        # Add an overlay file next to the manifest
        overlay_dir = tmp_path / "overlays"
        overlay_dir.mkdir()
        (overlay_dir / "wardline.overlay.yaml").write_text("overlay_for: x\n")

        hash_after = _compute_manifest_hash(manifest)
        assert hash_before == hash_after

    def test_manifest_hash_returns_none_on_missing_file(self, tmp_path: Path) -> None:
        """Missing manifest returns None."""
        from wardline.cli.scan import _compute_manifest_hash

        result = _compute_manifest_hash(tmp_path / "nonexistent.yaml")
        assert result is None


class TestComputeInputHash:
    def test_deterministic(self, tmp_path: Path) -> None:
        """Same files produce same hash."""
        from wardline.cli.scan import _compute_input_hash

        f1 = tmp_path / "a.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2 = tmp_path / "b.py"
        f2.write_text("y = 2\n", encoding="utf-8")

        hash1, count1 = _compute_input_hash([f1, f2], tmp_path)
        hash2, count2 = _compute_input_hash([f1, f2], tmp_path)
        assert hash1 == hash2
        assert count1 == count2 == 2
        assert hash1.startswith("sha256:")

    def test_order_independent(self, tmp_path: Path) -> None:
        """Different enumeration order produces same hash."""
        from wardline.cli.scan import _compute_input_hash

        f1 = tmp_path / "a.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2 = tmp_path / "b.py"
        f2.write_text("y = 2\n", encoding="utf-8")

        hash_ab, _ = _compute_input_hash([f1, f2], tmp_path)
        hash_ba, _ = _compute_input_hash([f2, f1], tmp_path)
        assert hash_ab == hash_ba

    def test_empty_file_set(self, tmp_path: Path) -> None:
        """Empty file set produces valid hash with count 0."""
        from wardline.cli.scan import _compute_input_hash

        h, count = _compute_input_hash([], tmp_path)
        assert h.startswith("sha256:")
        assert count == 0
        assert len(h) == len("sha256:") + 64

    def test_symlink_dedup(self, tmp_path: Path) -> None:
        """Symlink to same file is counted once."""
        from wardline.cli.scan import _compute_input_hash

        real = tmp_path / "real.py"
        real.write_text("x = 1\n", encoding="utf-8")
        link = tmp_path / "link.py"
        link.symlink_to(real)

        h_both, count_both = _compute_input_hash([real, link], tmp_path)
        h_real, count_real = _compute_input_hash([real], tmp_path)
        assert h_both == h_real
        assert count_both == count_real == 1

    def test_uses_project_root_not_scan_path(self, tmp_path: Path) -> None:
        """Paths are relative to project_root, not to wherever the scan started."""
        from wardline.cli.scan import _compute_input_hash

        sub = tmp_path / "src"
        sub.mkdir()
        f = sub / "mod.py"
        f.write_text("x = 1\n", encoding="utf-8")

        h_root, _ = _compute_input_hash([f], tmp_path)
        h_sub, _ = _compute_input_hash([f], sub)
        assert h_root != h_sub

    def test_hard_failure_on_unreadable(self, tmp_path: Path) -> None:
        """OSError on read_bytes raises, does not silently skip."""
        from wardline.cli.scan import _compute_input_hash

        missing = tmp_path / "gone.py"
        with pytest.raises(OSError):
            _compute_input_hash([missing], tmp_path)


class TestComputeDeferredFixRatio:
    def test_zero_active_returns_zero(self) -> None:
        """No active exceptions → 0.0 (not None — nothing to defer)."""
        from wardline.cli.scan import _compute_deferred_fix_ratio
        assert _compute_deferred_fix_ratio(0, 0) == 0.0

    def test_active_but_zero_deferred_returns_none(self) -> None:
        """Unclassified exceptions — none have elimination_path."""
        from wardline.cli.scan import _compute_deferred_fix_ratio
        assert _compute_deferred_fix_ratio(10, 0) is None

    def test_all_deferred_returns_one(self) -> None:
        from wardline.cli.scan import _compute_deferred_fix_ratio
        assert _compute_deferred_fix_ratio(5, 5) == 1.0

    def test_partial_deferred_returns_ratio(self) -> None:
        from wardline.cli.scan import _compute_deferred_fix_ratio
        assert _compute_deferred_fix_ratio(4, 1) == 0.25

    def test_single_active_single_deferred(self) -> None:
        from wardline.cli.scan import _compute_deferred_fix_ratio
        assert _compute_deferred_fix_ratio(1, 1) == 1.0


class TestComputeOverlayHashes:
    def test_sorted_by_normalized_path(self, tmp_path: Path) -> None:
        """Overlay hashes are sorted by forward-slash path relative to project root."""
        from wardline.cli.scan import _compute_overlay_hashes

        d1 = tmp_path / "z_dir"
        d1.mkdir()
        d2 = tmp_path / "a_dir"
        d2.mkdir()
        o1 = d1 / "wardline.overlay.yaml"
        o1.write_bytes(b"overlay_for: z_dir\n")
        o2 = d2 / "wardline.overlay.yaml"
        o2.write_bytes(b"overlay_for: a_dir\n")

        result = _compute_overlay_hashes([o1, o2], tmp_path)
        assert len(result) == 2
        assert all(h.startswith("sha256:") for h in result)
        # a_dir sorts before z_dir
        h_a = _compute_overlay_hashes([o2], tmp_path)
        h_z = _compute_overlay_hashes([o1], tmp_path)
        assert result == (h_a[0], h_z[0])

    def test_empty_returns_empty_tuple(self, tmp_path: Path) -> None:
        """No overlays returns empty tuple."""
        from wardline.cli.scan import _compute_overlay_hashes

        result = _compute_overlay_hashes([], tmp_path)
        assert result == ()

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        """Symlinked overlay files are excluded."""
        from wardline.cli.scan import _compute_overlay_hashes

        real = tmp_path / "real.yaml"
        real.write_bytes(b"overlay_for: x\n")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)

        result = _compute_overlay_hashes([real, link], tmp_path)
        assert len(result) == 1

    def test_path_order_differs_from_hash_order(self, tmp_path: Path) -> None:
        """Overlay hashes sorted by POSIX path, not by hash value (§10.1)."""
        import hashlib

        from wardline.cli.scan import _compute_overlay_hashes

        overlays_dir = tmp_path / "overlays"
        (overlays_dir / "a").mkdir(parents=True)
        (overlays_dir / "b").mkdir(parents=True)

        # Content deliberately chosen so hash-alphabetical order
        # differs from path-alphabetical order.
        files = {
            overlays_dir / "a" / "z.yaml": b"overlay_for: a/z\n",
            overlays_dir / "b" / "a.yaml": b"overlay_for: b/a\n",
            overlays_dir / "a" / "a.yaml": b"overlay_for: a/a\n",
        }
        for path, content in files.items():
            path.write_bytes(content)

        # Pass in NON-sorted order to verify internal sorting.
        result = _compute_overlay_hashes(
            [overlays_dir / "b" / "a.yaml",
             overlays_dir / "a" / "z.yaml",
             overlays_dir / "a" / "a.yaml"],
            tmp_path,
        )

        def sha(content: bytes) -> str:
            return f"sha256:{hashlib.sha256(content).hexdigest()}"

        expected = (
            sha(b"overlay_for: a/a\n"),   # overlays/a/a.yaml
            sha(b"overlay_for: a/z\n"),   # overlays/a/z.yaml
            sha(b"overlay_for: b/a\n"),   # overlays/b/a.yaml
        )
        assert result == expected


class TestReadCoverageRatio:
    def test_no_baseline_returns_none(self, tmp_path: Path) -> None:
        """No fingerprint baseline file returns None."""
        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        result = _read_coverage_ratio(manifest)
        assert result is None

    def test_baseline_with_ratio(self, tmp_path: Path) -> None:
        """Fingerprint baseline with coverage.ratio returns float."""
        import json

        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text(
            json.dumps({"coverage": {"ratio": 0.73, "annotated": 30, "total": 41}})
        )
        result = _read_coverage_ratio(manifest)
        assert result == 0.73

    def test_baseline_with_zero_ratio(self, tmp_path: Path) -> None:
        """Baseline exists but ratio is 0.0 — returns 0.0, not None."""
        import json

        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text(json.dumps({"coverage": {"ratio": 0.0}}))
        result = _read_coverage_ratio(manifest)
        assert result == 0.0

    def test_corrupt_baseline_returns_none(self, tmp_path: Path) -> None:
        """Corrupt JSON baseline returns None (not crash)."""
        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text("NOT JSON")
        result = _read_coverage_ratio(manifest)
        assert result is None
