"""wardline explain — show taint resolution for a function."""

from __future__ import annotations

import ast
import json as json_mod
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

import click

from wardline.cli._helpers import cli_error
from wardline.cli.scan import EXIT_CONFIG_ERROR


@click.command()
@click.argument("qualname")
@click.option(
    "--manifest",
    type=click.Path(),
    default=None,
    help="Path to wardline.yaml manifest.",
)
@click.option(
    "--path",
    "scan_path",
    type=click.Path(exists=True),
    default=".",
    help="Root path to search for the function.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
)
def explain(
    qualname: str,
    manifest: str | None,
    scan_path: str,
    output_json: bool,
) -> None:
    """Show taint resolution path for a function.

    QUALNAME is the qualified name of the function (e.g., 'MyClass.process').
    """
    from wardline.core.matrix import lookup
    from wardline.core.severity import RuleId
    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.scanner.discovery import discover_annotations
    from wardline.scanner.sarif import _PSEUDO_RULE_IDS
    from wardline.scanner.taint.function_level import (
        BODY_EVAL_TAINT,
        RETURN_TAINT,
        assign_function_taints,
        resolve_module_default,
        taint_from_annotations,
    )

    # Load manifest
    manifest_model = None
    manifest_path = Path(manifest) if manifest is not None else discover_manifest(Path(scan_path))

    if manifest is not None and manifest_path is not None and not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_path}")
        sys.exit(EXIT_CONFIG_ERROR)

    if manifest_path is not None and manifest_path.exists():
        try:
            manifest_model = load_manifest(manifest_path)
        except (WardlineYAMLError, ManifestLoadError) as exc:
            cli_error(f"malformed manifest: {exc}")
            sys.exit(EXIT_CONFIG_ERROR)
        except OSError as exc:
            click.echo(f"warning: could not load manifest: {exc}", err=True)

    # Search for the function in Python files
    root = Path(scan_path).resolve()
    found = False

    for py_file in sorted(root.rglob("*.py")):
        # Skip hidden dirs, __pycache__, .venv, etc.
        parts = py_file.parts
        if any(
            p.startswith(".") or p == "__pycache__" or p == ".venv"
            for p in parts
        ):
            continue

        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        file_path_str = str(py_file)

        # Discover annotations and assign taints
        annotations = discover_annotations(tree, file_path_str)
        taint_map, _return_taint_map, _taint_sources, _conflicts, _overclaims = assign_function_taints(
            tree, file_path_str, annotations, manifest_model
        )

        if qualname not in taint_map:
            continue

        # Found the function
        found = True
        taint = taint_map[qualname]

        # Build result dict for --json mode
        result: dict[str, Any] = {
            "qualname": qualname,
            "file": str(py_file),
            "taint_state": str(taint),
        }

        if not output_json:
            click.echo(f"Function: {qualname}")
            click.echo(f"File: {py_file}")
            click.echo(f"Taint state: {taint}")
            click.echo()

        # Determine how taint was resolved
        decorator_taint = taint_from_annotations(
            file_path_str, qualname, annotations
        )
        module_default = resolve_module_default(
            file_path_str, manifest_model,
            project_root=manifest_path.parent if manifest_path is not None else None,
        )

        if decorator_taint is not None:
            # Find which decorator(s) matched
            key = (file_path_str, qualname)
            annots = annotations.get(key, [])
            matching = [
                a.canonical_name
                for a in annots
                if a.canonical_name in BODY_EVAL_TAINT
            ]
            # Resolve return taint (OUTPUT tier) for display
            return_taint = taint_from_annotations(
                file_path_str, qualname, annotations, decorator_map=RETURN_TAINT,
            )
            result["resolution"] = {
                "source": "decorator",
                "decorators": matching,
            }
            result["body_eval_taint"] = str(decorator_taint)
            result["return_taint"] = str(return_taint) if return_taint else str(decorator_taint)
            result["module_default"] = str(module_default) if module_default is not None else None
            if not output_json:
                click.echo(f"Resolution: decorator ({', '.join(matching)})")
                if return_taint is not None and return_taint != decorator_taint:
                    click.echo(f"  Body eval taint: {decorator_taint} (input tier)")
                    click.echo(f"  Return taint: {return_taint} (output tier)")
                else:
                    click.echo(f"  Decorator taint: {decorator_taint}")
                if module_default is not None:
                    click.echo(f"  Module default (overridden): {module_default}")
        elif module_default is not None:
            result["resolution"] = {
                "source": "module_tiers",
            }
            result["module_default"] = str(module_default)
            if not output_json:
                # Find which module_tiers entry matched
                click.echo("Resolution: module_tiers entry")
                if manifest_model is not None:
                    from pathlib import PurePath

                    file_p = PurePath(file_path_str)
                    for mt in manifest_model.module_tiers:
                        entry_p = PurePath(mt.path)
                        try:
                            file_p.relative_to(entry_p)
                            click.echo(f"  Matched path: {mt.path}")
                            click.echo(f"  Default taint: {mt.default_taint}")
                            break
                        except ValueError:
                            continue
        else:
            result["resolution"] = {
                "source": "fallback",
            }
            result["module_default"] = None
            if not output_json:
                click.echo("Resolution: UNKNOWN_RAW (fallback)")
                if manifest_model is None:
                    click.echo("  Reason: no manifest loaded")
                else:
                    click.echo(
                        "  Reason: module not declared in module_tiers"
                    )

        # Report unresolved decorators
        key = (file_path_str, qualname)
        annots = annotations.get(key, [])
        unresolved = [
            a
            for a in annots
            if a.canonical_name not in BODY_EVAL_TAINT
            and a.canonical_name != ""
        ]
        result["unresolved_decorators"] = [a.canonical_name for a in unresolved]
        if not output_json and unresolved:
            click.echo()
            click.echo("Unresolved decorators:")
            for a in unresolved:
                click.echo(f"  - {a.canonical_name}")

        # Show which rules would evaluate and at what severity
        canonical_rules = [
            r
            for r in RuleId
            if r not in _PSEUDO_RULE_IDS
        ]
        rules_list: list[dict[str, Any]] = []
        if not output_json:
            click.echo()
            click.echo("Rules evaluated at this taint state:")
        for rule_id in sorted(canonical_rules, key=lambda r: r.value):
            try:
                cell = lookup(rule_id, taint)
                rules_list.append({
                    "rule_id": str(rule_id),
                    "severity": str(cell.severity),
                    "exceptionability": str(cell.exceptionability),
                })
                if not output_json:
                    click.echo(
                        f"  {rule_id}: severity={cell.severity}, "
                        f"exceptionability={cell.exceptionability}"
                    )
            except KeyError:
                pass
        result["rules"] = rules_list

        # ── Exception status section ──────────────────────────────
        exceptions_data = _build_exception_section(
            qualname, str(taint), file_path_str, root, manifest_path,
            canonical_rules, output_json,
        )
        result["exceptions"] = exceptions_data

        # ── Overlay resolution section ────────────────────────────
        overlay_data = _build_overlay_section(
            tree, qualname, taint_map, file_path_str, root, manifest_model, output_json,
        )
        result["overlay"] = overlay_data

        # ── Fingerprint state section ─────────────────────────────
        fingerprint_data = _build_fingerprint_section(
            py_file, qualname, manifest_model, manifest_path, output_json,
        )
        result["fingerprint"] = fingerprint_data

        if output_json:
            click.echo(json_mod.dumps(result, indent=2))

        break  # Only show first match

    if not found:
        if output_json:
            click.echo(json_mod.dumps({"error": f"function '{qualname}' not found"}))
        else:
            cli_error(f"function '{qualname}' not found")
        sys.exit(1)


def _build_exception_section(
    qualname: str,
    taint_state: str,
    file_path_str: str,
    root: Path,
    manifest_path: Path | None,
    canonical_rules: list[Any],
    output_json: bool,
) -> list[dict[str, Any]]:
    """Build exception status section for the explain output."""
    import datetime

    from wardline.manifest.exceptions import load_exceptions

    exceptions_list: list[dict[str, Any]] = []
    all_exceptions: tuple[Any, ...] = ()

    if manifest_path is not None and manifest_path.exists():
        try:
            all_exceptions = load_exceptions(manifest_path.parent)
        except (OSError, ValueError) as exc:
            click.echo(f"warning: could not load exception register: {exc}", err=True)

    # Build relative location key for matching — use manifest root (not --path)
    # to match how exceptions are stored and how wardline scan matches them.
    exception_root = manifest_path.parent.resolve() if manifest_path is not None else root
    try:
        rel_path = str(Path(file_path_str).relative_to(exception_root))
    except ValueError:
        rel_path = file_path_str
    location_key = f"{rel_path}::{qualname}"

    now = datetime.date.today()

    if not output_json:
        click.echo()
        click.echo("Exceptions:")

    for rule_id in sorted(canonical_rules, key=lambda r: r.value):
        rule_str = str(rule_id)
        # Find matching exception for this (rule, taint_state, location)
        matched_exc = None
        for exc_entry in all_exceptions:
            exc_location = exc_entry.location
            if exc_entry.rule == rule_str and exc_entry.taint_state == taint_state and exc_location == location_key:
                matched_exc = exc_entry
                break

        if matched_exc is not None:
            # Determine active/expired status
            status = "active"
            if matched_exc.expires is not None:
                try:
                    expiry = datetime.date.fromisoformat(matched_exc.expires)
                    if expiry < now:
                        status = "expired"
                except ValueError:
                    pass

            exc_info: dict[str, Any] = {
                "rule": rule_str,
                "id": matched_exc.id,
                "status": status,
                "expires": matched_exc.expires,
                "governance_path": str(matched_exc.governance_path),
                "recurrence_count": matched_exc.recurrence_count,
            }
            exceptions_list.append(exc_info)

            if not output_json:
                expires_str = f", expires {matched_exc.expires}" if matched_exc.expires else ""
                click.echo(f"  {rule_str}  {matched_exc.id} ({status}{expires_str})")
                click.echo(f'             Rationale: "{matched_exc.rationale}"')
                click.echo(f"             Reviewer: {matched_exc.reviewer}")
                click.echo(f"             Governance path: {matched_exc.governance_path}")
                click.echo(f"             Recurrence: {matched_exc.recurrence_count}")
        else:
            exceptions_list.append({
                "rule": rule_str,
                "id": None,
                "status": "none",
            })
            if not output_json:
                click.echo(f"  {rule_str}  (no exception)")

    return exceptions_list


def _build_overlay_section(
    tree: ast.Module,
    qualname: str,
    taint_map: Mapping[str, object],
    file_path_str: str,
    root: Path,
    manifest_model: object | None,
    output_json: bool,
) -> dict[str, Any] | None:
    """Build overlay resolution section for the explain output."""
    from wardline.manifest.loader import ManifestLoadError
    from wardline.manifest.resolve import resolve_boundaries, resolve_optional_fields
    from wardline.manifest.scope import path_within_scope, scope_specificity
    from wardline.scanner.context import ScanContext
    from wardline.scanner.rules.py_wl_001 import RulePyWl001

    if manifest_model is None:
        if not output_json:
            click.echo()
            click.echo("Overlay: none (no manifest loaded)")
        return None

    try:
        boundaries, _ = resolve_boundaries(root, manifest_model)  # type: ignore[arg-type]
        optional_fields = resolve_optional_fields(root, manifest_model)  # type: ignore[arg-type]
    except (ManifestLoadError, OSError) as exc:
        if not output_json:
            click.echo()
            click.echo(f"Overlay: error resolving overlays: {exc}")
        return None

    # Filter boundaries by scope matching the file
    resolved_file = str(Path(file_path_str).resolve())
    matching_boundaries = [
        b for b in boundaries
        if b.overlay_scope and path_within_scope(resolved_file, b.overlay_scope)
    ]

    if not matching_boundaries:
        if not output_json:
            click.echo()
            click.echo("Overlay: none (module not covered by any overlay)")
        return None

    # Find the overlay path — derive from scope
    scope = max(
        (b.overlay_scope for b in matching_boundaries),
        key=scope_specificity,
    )
    try:
        rel_scope = str(Path(scope).relative_to(root)) + "/"
    except ValueError:
        rel_scope = scope

    # Find actual overlay file path
    overlay_file_path = _find_overlay_path(root, rel_scope)
    boundary_transitions = [b.transition for b in matching_boundaries]
    rule = RulePyWl001(file_path=file_path_str)
    rule.set_context(
        ScanContext(
            file_path=file_path_str,
            function_level_taint_map=taint_map,  # type: ignore[arg-type]
            boundaries=tuple(boundaries),
            optional_fields=tuple(optional_fields),
        )
    )
    rule.visit(tree)
    governed_count = 0
    ungoverned_count = 0
    for finding in rule.findings:
        if finding.qualname != qualname:
            continue
        if finding.rule_id.value == "PY-WL-001-GOVERNED-DEFAULT":
            governed_count += 1
        elif finding.rule_id.value == "PY-WL-001-UNGOVERNED-DEFAULT":
            ungoverned_count += 1

    overlay_info: dict[str, Any] = {
        "path": str(overlay_file_path) if overlay_file_path else rel_scope,
        "scope": rel_scope,
        "boundaries": len(matching_boundaries),
        "schema_default_governed": governed_count > 0,
        "schema_default_ungoverned": ungoverned_count > 0,
        "schema_default_calls": governed_count + ungoverned_count,
    }

    if not output_json:
        click.echo()
        click.echo("Overlay:")
        click.echo(f"  Governed by: {overlay_info['path']}")
        click.echo(f"  Scope: {rel_scope}")
        click.echo(
            f"  Boundaries declared: {len(matching_boundaries)} "
            f"({', '.join(boundary_transitions)})"
        )
        if governed_count > 0:
            governed_str = "governed"
        elif ungoverned_count > 0:
            governed_str = "ungoverned"
        else:
            governed_str = "none detected in target function"
        click.echo(f"  schema_default() status: {governed_str}")

    return overlay_info


def _find_overlay_path(root: Path, rel_scope: str) -> str | None:
    """Find the overlay YAML file path relative to root for a given scope."""
    from wardline.manifest.discovery import OVERLAY_FILENAME

    # Look for overlay file in the scope directory
    scope_dir = root / rel_scope.rstrip("/")
    overlay_candidate = scope_dir / OVERLAY_FILENAME
    if overlay_candidate.exists():
        try:
            return str(overlay_candidate.relative_to(root))
        except ValueError:
            return str(overlay_candidate)

    # Search parent directories within scope
    for parent in [scope_dir] + list(scope_dir.parents):
        if parent == root.parent:
            break
        candidate = parent / OVERLAY_FILENAME
        if candidate.exists():
            try:
                return str(candidate.relative_to(root))
            except ValueError:
                return str(candidate)

    return None


def _build_fingerprint_section(
    py_file: Path,
    qualname: str,
    manifest_model: object | None,
    manifest_path: Path | None,
    output_json: bool,
) -> dict[str, Any]:
    """Build fingerprint state section for the explain output."""
    import json as _json

    from wardline.scanner.fingerprint import compute_single_annotation_fingerprint

    if manifest_model is None:
        if not output_json:
            click.echo()
            click.echo("Fingerprint:")
            click.echo("  Annotation hash: (no manifest)")
            click.echo("  Baseline match: no baseline stored")
        return {
            "annotation_hash": None,
            "baseline_match": None,
            "baseline_status": "no manifest",
        }

    # Compute current fingerprint
    entry = compute_single_annotation_fingerprint(py_file, qualname, manifest_model)  # type: ignore[arg-type]

    if entry is None:
        if not output_json:
            click.echo()
            click.echo("Fingerprint:")
            click.echo("  Annotation hash: (no annotations)")
            click.echo("  Baseline match: no baseline stored")
        return {
            "annotation_hash": None,
            "baseline_match": None,
            "baseline_status": "no annotations",
        }

    current_hash = entry.annotation_hash

    # Load baseline if available
    baseline_match: bool | None = None
    baseline_status = "no baseline stored"
    if manifest_path is not None:
        baseline_path = manifest_path.parent / "wardline.fingerprint.json"
        if baseline_path.exists():
            try:
                baseline_data = _json.loads(
                    baseline_path.read_text(encoding="utf-8")
                )
                # Compat: old baselines used "entries", new ones use "fingerprints"
                baseline_entries = baseline_data.get("fingerprints", baseline_data.get("entries", []))
                # Find matching entry by qualified_name
                for be in baseline_entries:
                    if be.get("qualified_name") == qualname:
                        stored_hash = be.get("annotation_hash", "")
                        if stored_hash == current_hash:
                            baseline_match = True
                            last_changed = be.get("last_changed", "")
                            baseline_status = f"yes (unchanged since {last_changed})" if last_changed else "yes"
                        else:
                            baseline_match = False
                            baseline_status = "MODIFIED (decorators changed since baseline)"
                        break
                else:
                    baseline_status = "no baseline stored"
            except (OSError, ValueError, KeyError, _json.JSONDecodeError):
                baseline_status = "no baseline stored"

    if not output_json:
        click.echo()
        click.echo("Fingerprint:")
        click.echo(f"  Annotation hash: {current_hash}")
        click.echo(f"  Baseline match: {baseline_status}")

    return {
        "annotation_hash": current_hash,
        "baseline_match": baseline_match,
    }
