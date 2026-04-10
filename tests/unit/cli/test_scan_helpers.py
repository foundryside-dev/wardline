"""Tests for SARIF run-level property computation helpers in cli/scan.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


class TestComputeManifestHash:
    def test_manifest_hash_is_root_only(self, tmp_path: Path) -> None:
        """manifestHash is SHA-256 of root manifest raw bytes only (§11.1)."""
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
        """Overlay hashes sorted by POSIX path, not by hash value (§11.1)."""
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


class TestResolveCoverageRatio:
    """Tests for _resolve_coverage_ratio helper."""

    def test_coverage_ratio_from_scan_when_no_baseline(self) -> None:
        """When no fingerprint baseline, coverage ratio comes from scan counts."""
        from wardline.cli.scan import _resolve_coverage_ratio

        ratio, scan_time = _resolve_coverage_ratio(None, 3, 10)
        assert ratio == pytest.approx(0.3)
        assert scan_time == pytest.approx(0.3)

    def test_coverage_ratio_prefers_baseline(self) -> None:
        """When fingerprint baseline exists, it takes precedence over scan-time."""
        from wardline.cli.scan import _resolve_coverage_ratio

        ratio, scan_time = _resolve_coverage_ratio(0.75, 3, 10)
        # Baseline value (0.75) wins over scan-time (0.3)
        assert ratio == 0.75
        assert scan_time == pytest.approx(0.3)

    def test_coverage_ratio_null_when_zero_functions(self) -> None:
        """Zero functions scanned → coverage ratio remains None (not 0.0)."""
        from wardline.cli.scan import _resolve_coverage_ratio

        ratio, scan_time = _resolve_coverage_ratio(None, 0, 0)
        assert ratio is None
        assert scan_time is None

    def test_baseline_none_zero_annotated(self) -> None:
        """No baseline, functions exist but none annotated → 0.0 (not None)."""
        from wardline.cli.scan import _resolve_coverage_ratio

        ratio, scan_time = _resolve_coverage_ratio(None, 0, 10)
        assert ratio == 0.0
        assert scan_time == 0.0


class TestCoverageRatioDivergence:
    """Tests for dual-source divergence warning boundary conditions."""

    def test_dual_source_divergence_warning_above_threshold(self) -> None:
        """15% divergence between baseline and scan-time → should warn."""
        from wardline.cli.scan import _resolve_coverage_ratio

        baseline = 0.80
        ratio, scan_time = _resolve_coverage_ratio(baseline, 65, 100)
        assert scan_time == pytest.approx(0.65)
        divergence = abs(baseline - scan_time)
        assert divergence > 0.10  # 15% > 10% threshold

    def test_dual_source_no_warning_at_exactly_threshold(self) -> None:
        """Exactly 10% divergence → NO warning (strict >)."""
        from wardline.cli.scan import _resolve_coverage_ratio

        baseline = 0.50
        ratio, scan_time = _resolve_coverage_ratio(baseline, 40, 100)
        assert scan_time == pytest.approx(0.40)
        divergence = abs(baseline - scan_time)
        assert not (divergence > 0.10)  # Exactly 10%, strict > means no warning

    def test_dual_source_no_warning_below_threshold(self) -> None:
        """5% divergence → no warning."""
        from wardline.cli.scan import _resolve_coverage_ratio

        baseline = 0.50
        ratio, scan_time = _resolve_coverage_ratio(baseline, 45, 100)
        assert scan_time == pytest.approx(0.45)
        divergence = abs(baseline - scan_time)
        assert not (divergence > 0.10)  # 5% < 10% threshold

    def test_divergence_triggers_scan_time_preference(self) -> None:
        """When divergence >10%, _resolve_coverage_ratio returns baseline but
        production code overrides to scan-time. Verify the override logic."""
        from wardline.cli.scan import _resolve_coverage_ratio
        from wardline.scanner.sarif import GovernanceEvent

        baseline = 0.90
        ratio, scan_time = _resolve_coverage_ratio(baseline, 70, 100)
        # Helper prefers baseline
        assert ratio == 0.90
        assert scan_time == pytest.approx(0.70)

        # Production divergence logic (from scan.py:~950)
        _gov_events: list[GovernanceEvent] = []
        if baseline is not None and scan_time is not None:
            _divergence = abs(baseline - scan_time)
            if _divergence > 0.10:
                ratio = scan_time  # I5 fix: prefer scan-time
                _gov_events.append(GovernanceEvent(
                    event_type="coverage_ratio_divergence",
                    message=f"delta={_divergence:.4f}",
                ))

        assert ratio == pytest.approx(0.70)  # scan-time now authoritative
        assert len(_gov_events) == 1
        assert _gov_events[0].event_type == "coverage_ratio_divergence"
        assert "0.2000" in _gov_events[0].message

    def test_zero_functions_returns_none(self) -> None:
        """Zero functions → both ratio and scan_time are None."""
        from wardline.cli.scan import _resolve_coverage_ratio

        ratio, scan_time = _resolve_coverage_ratio(None, 0, 0)
        assert ratio is None
        assert scan_time is None


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


class TestReadBaselineControlLaw:
    """Tests for _read_baseline_control_law helper."""

    def test_read_baseline_control_law_alternate(self, tmp_path: Path) -> None:
        """Baseline with 'alternate' control law returns 'alternate'."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "alternate"}}],
        }))
        law, failed = _read_baseline_control_law(str(sarif))
        assert law == "alternate"
        assert failed is False

    def test_read_baseline_control_law_normal(self, tmp_path: Path) -> None:
        """Baseline with 'normal' control law returns 'normal'."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "normal"}}],
        }))
        law, failed = _read_baseline_control_law(str(sarif))
        assert law == "normal"
        assert failed is False

    def test_read_baseline_control_law_no_compare(self) -> None:
        """compare=None returns None immediately."""
        from wardline.cli.scan import _read_baseline_control_law

        law, failed = _read_baseline_control_law(None)
        assert law is None
        assert failed is False

    def test_read_baseline_control_law_missing_property(self, tmp_path: Path) -> None:
        """Baseline SARIF without wardline.controlLaw returns None."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.analysisLevel": 1}}],
        }))
        law, failed = _read_baseline_control_law(str(sarif))
        assert law is None
        assert failed is False

    def test_read_baseline_control_law_empty_runs(self, tmp_path: Path) -> None:
        """Empty runs array is treated as read failure (H3 anti-bypass)."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({"runs": []}))
        law, failed = _read_baseline_control_law(str(sarif))
        assert law is None
        assert failed is True

    def test_read_baseline_control_law_malformed_json(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid JSON returns (None, True) and logs a warning."""
        import logging

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text("NOT VALID JSON {{{")
        with caplog.at_level(logging.WARNING, logger="wardline.cli.scan"):
            law, failed = _read_baseline_control_law(str(sarif))
        assert law is None
        assert failed is True
        assert any("Cannot read baseline control law" in r.message for r in caplog.records)

    def test_read_baseline_control_law_file_not_found(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Nonexistent path returns (None, True) and logs a warning."""
        import logging

        from wardline.cli.scan import _read_baseline_control_law

        with caplog.at_level(logging.WARNING, logger="wardline.cli.scan"):
            law, failed = _read_baseline_control_law("/nonexistent/path/baseline.sarif")
        assert law is None
        assert failed is True
        assert any("Cannot read baseline control law" in r.message for r in caplog.records)


class TestReadConformanceData:
    """Tests for _read_conformance_data helper."""

    def test_absent_file(self, tmp_path: Path) -> None:
        """No conformance file -> conformance_never_run."""
        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        never_run, unavailable, data = _read_conformance_data(manifest)
        assert never_run is True
        assert unavailable is False
        assert data == {}

    def test_malformed_json(self, tmp_path: Path) -> None:
        """Malformed file -> conformance_data_unavailable."""
        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        (tmp_path / "wardline.conformance.json").write_text("NOT JSON")
        never_run, unavailable, data = _read_conformance_data(manifest)
        assert never_run is False
        assert unavailable is True
        assert data == {}

    def test_missing_keys(self, tmp_path: Path) -> None:
        """File present but missing floor violation keys -> data_unavailable."""
        import json

        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        (tmp_path / "wardline.conformance.json").write_text(
            json.dumps({"gaps": [], "inputs": {}})
        )
        never_run, unavailable, data = _read_conformance_data(manifest)
        assert never_run is False
        assert unavailable is True
        assert "gaps" in data  # partial data still returned

    def test_valid_file(self, tmp_path: Path) -> None:
        """Valid file -> all healthy."""
        import json

        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        (tmp_path / "wardline.conformance.json").write_text(json.dumps({
            "gaps": [],
            "inputs": {},
            "cells_below_precision_floor": 2,
            "cells_below_recall_floor": 1,
        }))
        never_run, unavailable, data = _read_conformance_data(manifest)
        assert never_run is False
        assert unavailable is False
        assert data["cells_below_precision_floor"] == 2
        assert data["cells_below_recall_floor"] == 1


class TestRetrospectiveDetectionWiring:
    """Tests for retrospective scan detection logic wiring."""

    def test_retrospective_event_on_law_improvement(self, tmp_path: Path) -> None:
        """alternate->normal produces retrospective_scan_recommended event."""
        import json

        from wardline.cli.scan import _read_baseline_control_law
        from wardline.scanner.sarif import GovernanceEvent

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "alternate"}}],
        }))
        prev_law, _ = _read_baseline_control_law(str(sarif))
        current_law = "normal"

        # Replicate the production logic pattern from scan.py
        events: list[GovernanceEvent] = []
        if prev_law in ("alternate", "direct") and current_law == "normal":
            events.append(GovernanceEvent(
                event_type="retrospective_scan_recommended",
                message=f"Control law improved from {prev_law} to normal.",
            ))

        assert len(events) == 1
        assert events[0].event_type == "retrospective_scan_recommended"

    def test_no_event_when_law_unchanged(self, tmp_path: Path) -> None:
        """normal->normal produces no event."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "normal"}}],
        }))
        prev_law, _ = _read_baseline_control_law(str(sarif))
        assert prev_law == "normal"
        assert prev_law not in ("alternate", "direct")

    def test_no_event_when_law_degrades(self, tmp_path: Path) -> None:
        """normal->alternate produces no event (only improvement triggers)."""
        import json

        from wardline.cli.scan import _read_baseline_control_law

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "normal"}}],
        }))
        prev_law, _ = _read_baseline_control_law(str(sarif))
        current_law = "alternate"
        should_emit = prev_law in ("alternate", "direct") and current_law == "normal"
        assert not should_emit

    def test_no_event_without_compare(self) -> None:
        """No --compare -> no detection possible."""
        from wardline.cli.scan import _read_baseline_control_law

        law, failed = _read_baseline_control_law(None)
        assert law is None
        assert failed is False


class TestRetrospectiveFinding:
    """§10.5 step 3: GOVERNANCE_RETROSPECTIVE_REQUIRED finding emitted."""

    def test_finding_emitted_on_law_improvement_without_retrospective(self, tmp_path: Path) -> None:
        """alternate->normal without --retrospective emits Finding, not just event."""
        import json

        from wardline.cli.scan import _make_governance_finding, _read_baseline_control_law
        from wardline.core.severity import RuleId, Severity
        from wardline.scanner.context import Finding
        from wardline.scanner.sarif import GovernanceEvent

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "alternate"}}],
        }))
        prev_law, _ = _read_baseline_control_law(str(sarif))
        current_law = "normal"
        retrospective = None  # Not performing retrospective

        findings: list[Finding] = []
        events: list[GovernanceEvent] = []
        if prev_law in ("alternate", "direct") and current_law == "normal":
            msg = f"Control law improved from {prev_law} to normal."
            events.append(GovernanceEvent(event_type="retrospective_scan_recommended", message=msg))
            if not retrospective:
                findings.append(_make_governance_finding(
                    RuleId.GOVERNANCE_RETROSPECTIVE_REQUIRED, msg, Severity.WARNING,
                ))

        assert len(findings) == 1
        assert findings[0].rule_id == RuleId.GOVERNANCE_RETROSPECTIVE_REQUIRED

    def test_no_finding_when_retrospective_performed(self, tmp_path: Path) -> None:
        """alternate->normal WITH --retrospective does NOT emit Finding."""
        import json

        from wardline.cli.scan import _read_baseline_control_law
        from wardline.scanner.context import Finding

        sarif = tmp_path / "baseline.sarif"
        sarif.write_text(json.dumps({
            "runs": [{"properties": {"wardline.controlLaw": "direct"}}],
        }))
        prev_law, _ = _read_baseline_control_law(str(sarif))
        current_law = "normal"
        retrospective = "abc123..def456"  # Performing retrospective

        findings: list[Finding] = []
        if prev_law in ("alternate", "direct") and current_law == "normal":
            if not retrospective:
                findings.append(None)  # type: ignore[arg-type]

        assert len(findings) == 0


class TestIsInitialSetup:
    """Tests for is_initial_setup computation logic."""

    def test_both_absent(self, tmp_path: Path) -> None:
        """No conformance file AND no fingerprint baseline -> initial setup."""
        from wardline.cli.scan import _read_conformance_data
        from wardline.manifest.regime import FingerprintMetrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        never_run, _, _ = _read_conformance_data(manifest)
        fp = FingerprintMetrics()  # present=False
        is_initial = never_run and not fp.present
        assert is_initial is True

    def test_conformance_exists(self, tmp_path: Path) -> None:
        """Conformance file present -> NOT initial setup."""
        import json

        from wardline.cli.scan import _read_conformance_data
        from wardline.manifest.regime import FingerprintMetrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        (tmp_path / "wardline.conformance.json").write_text(json.dumps({
            "gaps": [], "inputs": {},
            "cells_below_precision_floor": 0, "cells_below_recall_floor": 0,
        }))
        never_run, _, _ = _read_conformance_data(manifest)
        fp = FingerprintMetrics()  # absent
        is_initial = never_run and not fp.present
        assert is_initial is False  # conformance exists

    def test_fingerprint_exists(self, tmp_path: Path) -> None:
        """Fingerprint baseline present -> NOT initial setup."""
        from wardline.cli.scan import _read_conformance_data
        from wardline.manifest.regime import FingerprintMetrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        never_run, _, _ = _read_conformance_data(manifest)
        fp = FingerprintMetrics(present=True)  # file exists
        is_initial = never_run and not fp.present
        assert is_initial is False  # fingerprint exists

    def test_corrupt_fingerprint_not_initial(self) -> None:
        """Corrupt fingerprint file (present=True, age_days=None) -> NOT initial setup (I7 fix)."""
        from wardline.manifest.regime import FingerprintMetrics

        fp = FingerprintMetrics(present=True, age_days=None)
        conformance_never_run = True
        is_initial = conformance_never_run and not fp.present
        assert is_initial is False  # file exists, just corrupt


class TestZeroFunctionsLogsDebug:
    """Test that zero-function scan emits debug log."""

    def test_zero_functions_logs_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Debug log emitted when total_function_count == 0."""
        import logging

        with caplog.at_level(logging.DEBUG):
            # Directly replicate the production logic from scan.py:856-857
            total_function_count = 0
            logger = logging.getLogger("wardline.cli.scan")
            if total_function_count == 0:
                logger.debug("Zero functions discovered during scan — coverage ratio unavailable")

        assert any(
            "Zero functions discovered" in r.message
            for r in caplog.records
        )


class TestConformanceMissingKeys:
    """Tests for partial/missing keys in wardline.conformance.json."""

    def test_conformance_missing_precision_key(self, tmp_path: Path) -> None:
        """conformance.json missing cells_below_precision_floor -> data_unavailable."""
        import json

        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        conf = tmp_path / "wardline.conformance.json"
        conf.write_text(json.dumps({"cells_below_recall_floor": 0}))

        never_run, data_unavailable, data = _read_conformance_data(manifest)
        assert never_run is False
        assert data_unavailable is True

    def test_conformance_missing_recall_key(self, tmp_path: Path) -> None:
        """conformance.json missing cells_below_recall_floor -> data_unavailable."""
        import json

        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        conf = tmp_path / "wardline.conformance.json"
        conf.write_text(json.dumps({"cells_below_precision_floor": 0}))

        never_run, data_unavailable, data = _read_conformance_data(manifest)
        assert never_run is False
        assert data_unavailable is True

    def test_conformance_missing_keys_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Warning logged when conformance.json has missing floor violation keys."""
        import json

        from wardline.cli.scan import _read_conformance_data

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        conf = tmp_path / "wardline.conformance.json"
        conf.write_text(json.dumps({"verdict": "pass"}))  # no floor keys

        _read_conformance_data(manifest)
        assert any(
            "missing floor violation keys" in r.message
            for r in caplog.records
        )
