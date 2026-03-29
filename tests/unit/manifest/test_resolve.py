"""Tests for wardline.manifest.resolve — boundary resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from wardline.manifest.discovery import GovernanceError
from wardline.manifest.loader import ManifestPolicyError
from wardline.manifest.merge import ManifestWidenError
from wardline.manifest.models import (
    ModuleTierEntry,
    TierEntry,
    WardlineManifest,
)
from wardline.manifest.resolve import resolve_boundaries

if TYPE_CHECKING:
    from pathlib import Path


def _write_overlay(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _minimal_manifest(
    module_paths: tuple[str, ...] = (),
    tiers: tuple[TierEntry, ...] = (),
) -> WardlineManifest:
    return WardlineManifest(
        module_tiers=tuple(
            ModuleTierEntry(path=p, default_taint="EXTERNAL_RAW")
            for p in module_paths
        ),
        tiers=tiers if tiers else (TierEntry(id="EXTERNAL_RAW", tier=4),),
    )


class TestResolveBoundaries:
    def test_no_overlays_returns_empty(self, tmp_path: Path) -> None:
        manifest = _minimal_manifest()
        result, _ = resolve_boundaries(tmp_path, manifest)
        assert result == ()

    def test_overlay_boundaries_returned_with_scope(self, tmp_path: Path) -> None:
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: adapters\n"
                "boundaries:\n"
                '  - function: "Handler.handle"\n'
                '    transition: "construction"\n'
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        result, _ = resolve_boundaries(tmp_path, manifest)

        assert len(result) == 1
        assert result[0].function == "Handler.handle"
        # overlay_scope is now absolute, resolved from root / overlay_for
        assert result[0].overlay_scope == str((tmp_path / "adapters").resolve())

    def test_governance_error_propagates(self, tmp_path: Path) -> None:
        """Overlay in undeclared directory raises GovernanceError."""
        rogue_dir = tmp_path / "rogue"
        rogue_dir.mkdir()
        _write_overlay(
            rogue_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: rogue\n"
                "boundaries: []\n"
            ),
        )
        manifest = _minimal_manifest()  # no module_tiers covering "rogue"

        with pytest.raises(GovernanceError):
            resolve_boundaries(tmp_path, manifest)

    def test_manifest_widen_error_propagates(self, tmp_path: Path) -> None:
        """ManifestWidenError from merge() propagates (not caught)."""
        overlay_dir = tmp_path / "core"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: core\n"
                "boundaries:\n"
                '  - function: "Handler.handle"\n'
                '    transition: "construction"\n'
                "    from_tier: 4\n"
            ),
        )
        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="core", default_taint="INTEGRAL"),),
            tiers=(
                TierEntry(id="INTEGRAL", tier=1),
                TierEntry(id="EXTERNAL_RAW", tier=4),
            ),
        )

        with pytest.raises(ManifestWidenError):
            resolve_boundaries(tmp_path, manifest)

    def test_bad_overlay_file_skipped(self, tmp_path: Path) -> None:
        """Overlay that fails to load is skipped, not crash."""
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        # Write a file that will fail schema validation
        (overlay_dir / "wardline.overlay.yaml").write_text(
            "this_is_not_valid_overlay: true\n", encoding="utf-8"
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        result, _ = resolve_boundaries(tmp_path, manifest)
        assert result == ()

    def test_overlay_for_path_mismatch_raises(self, tmp_path: Path) -> None:
        """Overlay claiming overlay_for that doesn't match its directory raises GovernanceError."""
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: audit\n"
                "boundaries: []\n"
            ),
        )
        # Allow both "adapters" and "audit" in discovery so we get past that check
        manifest = _minimal_manifest(module_paths=("adapters", "audit"))

        with pytest.raises(GovernanceError, match="overlay_for='audit'"):
            resolve_boundaries(tmp_path, manifest)

    def test_overlay_for_path_match_accepted(self, tmp_path: Path) -> None:
        """Overlay whose overlay_for matches its directory is accepted."""
        overlay_dir = tmp_path / "adapters" / "partner"
        overlay_dir.mkdir(parents=True)
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: adapters/partner\n"
                "boundaries:\n"
                '  - function: "Client.call"\n'
                '    transition: "construction"\n'
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        result, _ = resolve_boundaries(tmp_path, manifest)
        assert len(result) == 1

    def test_duplicate_boundary_functions_within_overlay_rejected(
        self, tmp_path: Path
    ) -> None:
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: adapters\n"
                "boundaries:\n"
                '  - function: "Client.call"\n'
                '    transition: "construction"\n'
                '  - function: "Client.call"\n'
                '    transition: "semantic_validation"\n'
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        with pytest.raises(
            GovernanceError,
            match="Duplicate boundary declaration for function 'Client.call'",
        ):
            resolve_boundaries(tmp_path, manifest)

    def test_skip_promotion_propagates_as_policy_error(
        self, tmp_path: Path
    ) -> None:
        """Overlay with skip-promotion (from_tier=4, to_tier=1) raises ManifestPolicyError."""
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: adapters\n"
                "boundaries:\n"
                '  - function: "Client.ingest"\n'
                '    transition: "construction"\n'
                "    from_tier: 4\n"
                "    to_tier: 1\n"
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        with pytest.raises(ManifestPolicyError, match="skip-promotions to Tier 1"):
            resolve_boundaries(tmp_path, manifest)

    def test_returns_boundaries_and_overlay_paths(self, tmp_path: Path) -> None:
        """resolve_boundaries() returns (boundaries, overlay_paths) tuple."""
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"\n'
                "overlay_for: adapters\n"
                "boundaries:\n"
                '  - function: "Handler.handle"\n'
                '    transition: "construction"\n'
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        boundaries, overlay_paths = resolve_boundaries(tmp_path, manifest)

        assert len(boundaries) == 1
        assert len(overlay_paths) == 1
        assert overlay_paths[0] == overlay_dir / "wardline.overlay.yaml"

    def test_no_overlays_returns_empty_tuple_pair(self, tmp_path: Path) -> None:
        """No overlays returns ((), ())."""
        manifest = _minimal_manifest()
        boundaries, overlay_paths = resolve_boundaries(tmp_path, manifest)
        assert boundaries == ()
        assert overlay_paths == ()
