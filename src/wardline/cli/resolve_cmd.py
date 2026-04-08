"""wardline resolve — produce wardline.resolved.json from manifest + overlays.

Runs the existing resolve_boundaries() pipeline, collects merged rule
overrides with provenance, and serialises everything to the resolved
overlay manifest format (spec version 0.1).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import click

from wardline.cli._helpers import cli_error

logger = logging.getLogger("wardline")


@click.command()
@click.option("--manifest", default=None, help="Path to wardline.yaml")
@click.option("--path", default=".", help="Project root to scan for overlays")
@click.option("-o", "--output", default=None, help="Output file (default: stdout)")
def resolve(manifest: str | None, path: str, output: str | None) -> None:
    """Resolve overlays and produce wardline.resolved.json."""
    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import ManifestLoadError, load_manifest, load_overlay
    from wardline.manifest.merge import merge
    from wardline.manifest.resolve import resolve_boundaries, resolve_optional_fields

    root = Path(path).resolve()

    # --- Locate manifest ---
    manifest_path: Path | None = None
    if manifest is not None:
        manifest_path = Path(manifest)
        if not manifest_path.exists():
            cli_error(f"manifest not found: {manifest}")
            sys.exit(2)
    else:
        manifest_path = discover_manifest(root)
        if manifest_path is None:
            manifest_path = discover_manifest(Path.cwd())
        if manifest_path is None:
            click.echo(
                f"error: no wardline.yaml found (searched from {root})",
                err=True,
            )
            sys.exit(2)

    manifest_model = load_manifest(manifest_path)

    # --- Validate manifest belongs to the overlay root ---
    resolved_manifest = manifest_path.resolve()
    try:
        resolved_manifest.relative_to(root)
    except ValueError:
        try:
            root.relative_to(resolved_manifest.parent)
        except ValueError:
            cli_error(
                f"Manifest {manifest_path} is outside the overlay root {root}. "
                f"This could mix one project's manifest with another project's "
                f"overlays. Use --path as a parent of the manifest, or omit "
                f"--manifest to auto-discover."
            )
            sys.exit(2)

    # --- Manifest hash ---
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()

    # --- Resolve boundaries (with overlay_path + overlay_scope) ---
    boundaries, overlay_file_paths = resolve_boundaries(root, manifest_model)
    optional_fields = resolve_optional_fields(root, manifest_model)

    # --- Build per-overlay summary + merged overrides ---

    import dataclasses

    overlays_discovered: list[dict[str, object]] = []
    all_governance_signals: list[dict[str, str]] = []
    current_rules = manifest_model.rules

    for overlay_path_item in overlay_file_paths:
        try:
            overlay = load_overlay(overlay_path_item)
        except (ManifestLoadError, OSError):
            continue

        rel_path = str(overlay_path_item.relative_to(root))
        overlays_discovered.append({
            "path": rel_path,
            "overlay_for": overlay.overlay_for,
            "boundary_count": len(overlay.boundaries),
            "rule_override_count": len(overlay.rule_overrides),
        })

        # Chain merges: feed accumulated rules as base so overrides accumulate
        temp_manifest = dataclasses.replace(manifest_model, rules=current_rules)
        resolved = merge(temp_manifest, overlay)
        current_rules = resolved.rules

        for signal in resolved.governance_signals:
            all_governance_signals.append({
                "level": signal.level,
                "message": signal.message,
                "overlay_path": rel_path,
            })

    merged_rule_overrides = current_rules.overrides

    # If no overlays, merged overrides come from base only
    if not overlay_file_paths:
        base_overrides: list[dict[str, object]] = []
        for ovr in manifest_model.rules.overrides:
            d = dict(ovr)
            d["source"] = "base"
            base_overrides.append(d)
        merged_rule_overrides = tuple(base_overrides)

    # --- Scanner config ---
    scanner_config_section: dict[str, object] | None = None
    toml_path = root / "wardline.toml"
    if toml_path.exists():
        from wardline.manifest.models import ScannerConfig, ScannerConfigError

        try:
            cfg = ScannerConfig.from_toml(toml_path)
            scanner_config_section = {
                "source": "wardline.toml",
                "analysis_level": cfg.analysis_level,
                "enabled_rules": [str(r.value) for r in cfg.enabled_rules],
                "disabled_rules": [str(r.value) for r in cfg.disabled_rules],
                "target_paths": [str(p) for p in cfg.target_paths],
                "exclude_paths": [str(p) for p in cfg.exclude_paths],
            }
        except ScannerConfigError:
            pass

    # --- Build resolved JSON ---
    resolved_json: dict[str, object] = {
        "format_version": "0.2",
        "resolved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "root": ".",
        "manifest_source": str(manifest_path.relative_to(root))
        if manifest_path.is_relative_to(root)
        else str(manifest_path),
        "manifest_hash": manifest_hash,
        "tiers": [
            {"id": t.id, "tier": t.tier, "description": t.description}
            for t in manifest_model.tiers
        ],
        "module_tiers": [
            {"path": mt.path, "default_taint": mt.default_taint}
            for mt in manifest_model.module_tiers
        ],
        "merged_rule_overrides": [dict(ovr) for ovr in merged_rule_overrides],
        "boundaries": [
            {
                "function": b.function,
                "transition": b.transition,
                "from_tier": b.from_tier,
                "to_tier": b.to_tier,
                "restored_tier": b.restored_tier,
                "provenance": b.provenance,
                "validation_scope": b.validation_scope,
                "overlay_scope": (
                    str(Path(b.overlay_scope).relative_to(root))
                    if b.overlay_scope else ""
                ),
                "overlay_path": b.overlay_path,
            }
            for b in boundaries
        ],
        "optional_fields": [
            {
                "field": f.field,
                "approved_default": f.approved_default,
                "rationale": f.rationale,
                "overlay_scope": (
                    str(Path(f.overlay_scope).relative_to(root))
                    if f.overlay_scope else ""
                ),
                "overlay_path": f.overlay_path,
            }
            for f in optional_fields
        ],
        "governance_signals": all_governance_signals,
        "overlays_discovered": overlays_discovered,
        "scanner_config": scanner_config_section,
        "metadata": {
            "organisation": manifest_model.metadata.organisation,
            "ratified_by": manifest_model.metadata.ratified_by,
            "ratification_date": manifest_model.metadata.ratification_date,
            "review_interval_days": manifest_model.metadata.review_interval_days,
        },
    }

    text = json.dumps(resolved_json, indent=2) + "\n"

    if output is not None:
        try:
            Path(output).write_text(text, encoding="utf-8")
        except OSError as exc:
            cli_error(f"cannot write to '{output}': {exc}")
            sys.exit(2)
    else:
        click.echo(text, nl=False)
