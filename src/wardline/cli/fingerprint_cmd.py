"""wardline fingerprint — annotation fingerprint baseline management.

``wardline fingerprint update`` computes and writes a fingerprint baseline.
``wardline fingerprint diff`` compares current annotations against a baseline.
"""

from __future__ import annotations

import json as json_mod
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click

from wardline.cli._helpers import cli_error
from wardline.cli.scan import EXIT_CONFIG_ERROR

# Exit codes
_EXIT_CLEAN = 0
_EXIT_GATE_FAILURE = 1



def _load_and_validate_baseline(
    baseline_path: Path,
) -> dict[str, Any]:
    """Load a fingerprint baseline JSON and validate against schema.

    Normalises old baselines (``entries`` -> ``fingerprints``, missing
    ``artefact_class``/``last_changed``) for backward compatibility.

    Returns the validated baseline dict.
    Calls ``sys.exit(EXIT_CONFIG_ERROR)`` on malformed JSON or schema failure.
    """
    import jsonschema

    try:
        raw = baseline_path.read_text(encoding="utf-8")
        data = json_mod.loads(raw)
    except (OSError, json_mod.JSONDecodeError) as exc:
        cli_error(f"malformed baseline: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    # --- Backward compat: normalise old field names ---
    # Old baselines use "entries" instead of "fingerprints"
    if "entries" in data and "fingerprints" not in data:
        data["fingerprints"] = data.pop("entries")

    # Strip unknown top-level keys that old baselines may have
    # (e.g. "schema_version") before validation against strict schema
    _KNOWN_TOP_KEYS = {"$id", "$schema", "python_version", "generated_at",
                       "coverage", "fingerprints"}
    for key in list(data.keys()):
        if key not in _KNOWN_TOP_KEYS:
            del data[key]

    # Normalise individual entries: supply defaults for missing fields
    for entry in data.get("fingerprints", []):
        entry.setdefault("artefact_class", "")
        entry.setdefault("last_changed", None)

    # --- Validate against schema ---
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "manifest" / "schemas" / "fingerprint.schema.json"
    )
    try:
        schema = json_mod.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as exc:
        cli_error(f"baseline schema validation failed: {exc.message}")
        sys.exit(EXIT_CONFIG_ERROR)
    except (OSError, json_mod.JSONDecodeError) as exc:
        cli_error(f"cannot load fingerprint schema: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    result: dict[str, Any] = data
    return result


def _deserialize_entries(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Deserialize fingerprint entries with backward-compat defaults."""
    entries = []
    for raw in data.get("fingerprints", []):
        entries.append({
            "qualified_name": raw.get("qualified_name", ""),
            "module": raw.get("module", ""),
            "decorators": tuple(raw.get("decorators", [])),
            "annotation_hash": raw.get("annotation_hash", ""),
            "tier_context": raw.get("tier_context", 4),
            "boundary_transition": raw.get("boundary_transition"),
            "last_changed": raw.get("last_changed"),
            "artefact_class": raw.get("artefact_class", ""),
        })
    return entries


@click.group()
def fingerprint() -> None:
    """Annotation fingerprint baseline management."""


@fingerprint.command("update")
@click.option(
    "--manifest",
    "manifest_file",
    type=click.Path(),
    required=True,
    help="Path to wardline.yaml manifest.",
)
@click.option(
    "--path",
    "scan_path",
    type=click.Path(exists=True),
    required=True,
    help="Root path to scan for Python files.",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
def update(
    manifest_file: str,
    scan_path: str,
    output_json: bool,
) -> None:
    """Compute and write annotation fingerprint baseline."""
    import yaml

    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.scanner.fingerprint import batch_compute_fingerprints

    # --- Load manifest ---
    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_file}")
        sys.exit(EXIT_CONFIG_ERROR)

    try:
        manifest_model = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        cli_error(f"malformed manifest: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    # --- Compute fingerprints ---
    root = Path(scan_path).resolve()
    entries, coverage = batch_compute_fingerprints(root, manifest_model)

    # --- Build baseline JSON ---
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    baseline = {
        "$id": "https://wardline.dev/schemas/1.0/fingerprint.schema.json",
        "python_version": python_version,
        "generated_at": datetime.now(UTC).isoformat(),
        "coverage": {
            "annotated": coverage.annotated,
            "total": coverage.total,
            "ratio": coverage.ratio,
            "tier1_annotated": coverage.tier1_annotated,
            "tier1_total": coverage.tier1_total,
            "tier1_unannotated": list(coverage.tier1_unannotated),
        },
        "fingerprints": [
            {
                "qualified_name": e.qualified_name,
                "module": e.module,
                "decorators": list(e.decorators),
                "annotation_hash": e.annotation_hash,
                "tier_context": e.tier_context,
                "boundary_transition": e.boundary_transition,
                "last_changed": e.last_changed,
                "artefact_class": e.artefact_class,
            }
            for e in entries
        ],
    }

    # --- Write baseline ---
    baseline_path = manifest_path.parent / "wardline.fingerprint.json"
    baseline_text = json_mod.dumps(baseline, indent=2) + "\n"
    baseline_path.write_text(baseline_text, encoding="utf-8")

    # --- Output ---
    if output_json:
        click.echo(json_mod.dumps({
            "baseline_path": str(baseline_path),
            "coverage": baseline["coverage"],
            "fingerprint_count": len(entries),
        }, indent=2))
    else:
        click.echo(f"wrote {baseline_path}")
        click.echo(
            f"coverage: {coverage.annotated}/{coverage.total} "
            f"({coverage.ratio:.0%})"
        )
        if coverage.tier1_total > 0:
            click.echo(
                f"tier 1: {coverage.tier1_annotated}/{coverage.tier1_total}"
            )


@fingerprint.command("diff")
@click.option(
    "--manifest",
    "manifest_file",
    type=click.Path(),
    required=True,
    help="Path to wardline.yaml manifest.",
)
@click.option(
    "--path",
    "scan_path",
    type=click.Path(exists=True),
    required=True,
    help="Root path to scan for Python files.",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
@click.option(
    "--gate",
    is_flag=True,
    help="Exit 1 if tier 1 annotations removed.",
)
@click.option(
    "--since",
    type=click.STRING,
    default=None,
    help="Only show changes after this ISO date (YYYY-MM-DD).",
)
def diff(
    manifest_file: str,
    scan_path: str,
    output_json: bool,
    gate: bool,
    since: str | None = None,
) -> None:
    """Compare current annotations against fingerprint baseline."""
    import yaml

    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.scanner.fingerprint import batch_compute_fingerprints

    # --- Load manifest ---
    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_file}")
        sys.exit(EXIT_CONFIG_ERROR)

    try:
        manifest_model = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        cli_error(f"malformed manifest: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    # --- Load baseline ---
    baseline_path = manifest_path.parent / "wardline.fingerprint.json"
    if not baseline_path.exists():
        click.echo("warning: no fingerprint baseline found", err=True)
        click.echo("0 changes (no baseline)")
        return

    baseline_data = _load_and_validate_baseline(baseline_path)
    baseline_entries = _deserialize_entries(baseline_data)

    # --- Check Python version mismatch ---
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    baseline_python_version = baseline_data.get("python_version", "")
    version_mismatch = (
        baseline_python_version != ""
        and baseline_python_version != python_version
    )

    # --- Compute current fingerprints ---
    root = Path(scan_path).resolve()
    current_entries, coverage = batch_compute_fingerprints(root, manifest_model)

    # --- Build lookup maps ---
    baseline_map: dict[str, dict[str, Any]] = {
        e["qualified_name"]: e for e in baseline_entries
    }
    current_map: dict[str, dict[str, Any]] = {
        e.qualified_name: {
            "qualified_name": e.qualified_name,
            "module": e.module,
            "decorators": list(e.decorators),
            "annotation_hash": e.annotation_hash,
            "tier_context": e.tier_context,
            "boundary_transition": e.boundary_transition,
            "last_changed": e.last_changed,
            "artefact_class": e.artefact_class,
        }
        for e in current_entries
    }

    # --- Compute diff ---
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []

    # Added: in current but not in baseline
    for qn, entry in current_map.items():
        if qn not in baseline_map:
            added.append({**entry, "change": "ADDED"})

    # Removed: in baseline but not in current
    for qn, entry in baseline_map.items():
        if qn not in current_map:
            removed.append({**entry, "change": "REMOVED"})

    # Modified: in both but hash differs (or version mismatch)
    for qn in baseline_map:
        if qn in current_map:
            b_hash = baseline_map[qn]["annotation_hash"]
            c_hash = current_map[qn]["annotation_hash"]
            if version_mismatch or b_hash != c_hash:
                entry = {**current_map[qn], "change": "MODIFIED"}
                if version_mismatch and b_hash == c_hash:
                    entry["reason"] = "python_version_mismatch"
                modified.append(entry)

    # --- Apply --since filter ---
    if since:
        from datetime import date as date_cls

        since_date = date_cls.fromisoformat(since)
        added = [
            e for e in added
            if e.get("last_changed") and date_cls.fromisoformat(e["last_changed"]) >= since_date
        ]
        modified = [
            e for e in modified
            if e.get("last_changed") and date_cls.fromisoformat(e["last_changed"]) >= since_date
        ]
        removed = [
            e for e in removed
            if e.get("last_changed") and date_cls.fromisoformat(e["last_changed"]) >= since_date
        ]

    total_changes = len(added) + len(removed) + len(modified)

    # --- Format output ---
    if output_json:
        result = {
            "added": added,
            "removed": removed,
            "modified": modified,
            "total_changes": total_changes,
            "coverage": {
                "annotated": coverage.annotated,
                "total": coverage.total,
                "ratio": coverage.ratio,
                "tier1_annotated": coverage.tier1_annotated,
                "tier1_total": coverage.tier1_total,
            },
        }
        if version_mismatch:
            result["python_version_mismatch"] = {
                "baseline": baseline_python_version,
                "current": python_version,
            }
        click.echo(json_mod.dumps(result, indent=2))
    else:
        if version_mismatch:
            click.echo(
                f"WARNING: Python version mismatch "
                f"(baseline: {baseline_python_version}, "
                f"current: {python_version})"
            )
            click.echo(
                "All fingerprints marked MODIFIED due to version change."
            )

        # Policy section
        policy_changes = [
            c for c in added + removed + modified
            if c.get("artefact_class") == "policy"
        ]
        if policy_changes:
            click.echo("\n[policy]")
            for c in policy_changes:
                click.echo(f"  {c['change']}: {c['qualified_name']}")

        # Enforcement section
        enforcement_changes = [
            c for c in added + removed + modified
            if c.get("artefact_class") != "policy"
        ]
        if enforcement_changes:
            click.echo("\n[enforcement]")
            for c in enforcement_changes:
                click.echo(f"  {c['change']}: {c['qualified_name']}")

        # Coverage report
        click.echo(
            f"\ncoverage: {coverage.annotated}/{coverage.total} "
            f"({coverage.ratio:.0%})"
        )

        click.echo(f"{total_changes} changes")

    # --- Gate logic ---
    # Exit 1 only on removed annotations in Tier 1 modules
    if gate:
        tier1_removals = [
            r for r in removed if r.get("tier_context") == 1
        ]
        if tier1_removals:
            if not output_json:
                click.echo(
                    f"GATE FAILED: {len(tier1_removals)} tier 1 "
                    f"annotation(s) removed",
                    err=True,
                )
            sys.exit(_EXIT_GATE_FAILURE)
