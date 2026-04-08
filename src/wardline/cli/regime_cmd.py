"""wardline regime status / wardline regime verify — governance health CLI.

``regime status`` is a read-only dashboard assembled from existing artifacts.
``regime verify`` runs coherence checks inline plus active verification checks,
optionally gating on ERROR-level failures.
"""

from __future__ import annotations

import json as json_mod
import logging
import sys
from pathlib import Path
from typing import Any

import click

from wardline.cli._helpers import COHERENCE_SEVERITY_MAP as _COHERENCE_SEVERITY_MAP
from wardline.cli._helpers import cli_error
from wardline.cli.scan import EXIT_CONFIG_ERROR

# Exit code 3: direct law — regime cannot produce meaningful enforcement
# output because no valid manifest exists (§A.10).
EXIT_DIRECT_LAW = 3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_all_annotations(
    scan_path: Path,
) -> dict[tuple[str, str], list[Any]]:
    """Walk .py files under *scan_path*, parse to AST, discover annotations."""
    from wardline.cli._helpers import discover_all_annotations

    return discover_all_annotations(scan_path)


def _run_coherence_checks(
    manifest_path: Path,
    scan_path: Path,
) -> tuple[list[Any], str | None]:
    """Run all 8 coherence checks inline and return the list of issues.

    Returns ``(issues, error)`` where *error* is a string if the manifest
    cannot be loaded, and *issues* is an empty list in that case.
    """
    import yaml

    from wardline.manifest.coherence import (
        check_agent_originated_exceptions,
        check_expired_exceptions,
        check_first_scan_perimeter,
        check_orphaned_annotations,
        check_tier_distribution,
        check_tier_downgrades,
        check_tier_upgrade_without_evidence,
        check_undeclared_boundaries,
    )
    from wardline.manifest.exceptions import load_exceptions
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.manifest.resolve import resolve_boundaries

    try:
        manifest_model = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        return [], str(exc)

    path_root = scan_path.resolve()
    annotations = _discover_all_annotations(path_root)

    manifest_dir = manifest_path.parent
    baseline_path = manifest_dir / "wardline.manifest.baseline.json"
    perimeter_baseline_path = manifest_dir / "wardline.perimeter.baseline.json"

    from wardline.manifest.discovery import GovernanceError

    try:
        boundaries, _ = resolve_boundaries(manifest_dir, manifest_model)
    except (GovernanceError, ManifestLoadError, OSError) as exc:
        logging.getLogger("wardline").warning(
            "Could not resolve boundaries: %s", exc,
        )
        boundaries = ()

    try:
        exceptions = load_exceptions(manifest_dir)
    except ManifestLoadError:
        exceptions = ()

    issues = []
    issues.extend(check_orphaned_annotations(annotations, boundaries))
    issues.extend(check_undeclared_boundaries(annotations, boundaries))
    issues.extend(
        check_tier_distribution(manifest_model.tiers, manifest_model.module_tiers)
    )
    issues.extend(
        check_tier_downgrades(
            manifest_model.tiers, manifest_model.module_tiers, baseline_path
        )
    )
    issues.extend(
        check_tier_upgrade_without_evidence(
            manifest_model.tiers,
            manifest_model.module_tiers,
            boundaries,
            baseline_path,
        )
    )
    issues.extend(check_agent_originated_exceptions(exceptions))
    issues.extend(check_expired_exceptions(exceptions))
    issues.extend(check_first_scan_perimeter(perimeter_baseline_path))

    return issues, None


# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group()
def regime() -> None:
    """Governance regime health — status dashboard and active verification."""


# ---------------------------------------------------------------------------
# regime status
# ---------------------------------------------------------------------------


@regime.command()
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
def status(
    manifest_file: str,
    scan_path: str,
    output_json: bool,
) -> None:
    """Read-only governance health dashboard."""
    from wardline.manifest.regime import (
        collect_exception_metrics,
        collect_fingerprint_metrics,
        collect_manifest_metrics,
        collect_rule_metrics,
    )

    import yaml

    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_file} — direct law applies")
        sys.exit(EXIT_DIRECT_LAW)

    # Validate manifest loads — if not, direct law applies (exit 3)
    try:
        load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError, OSError) as exc:
        cli_error(f"manifest invalid: {exc} — direct law applies")
        sys.exit(EXIT_DIRECT_LAW)

    manifest_dir = manifest_path.parent
    config_path = manifest_dir / "wardline.toml"

    manifest_m = collect_manifest_metrics(manifest_path)
    exception_m = collect_exception_metrics(manifest_dir)
    fingerprint_m = collect_fingerprint_metrics(manifest_dir)
    rule_m = collect_rule_metrics(manifest_path, config_path)

    if output_json:
        _status_json(manifest_m, exception_m, fingerprint_m, rule_m)
    else:
        _status_text(manifest_m, exception_m, fingerprint_m, rule_m)


def _status_text(manifest_m: Any, exception_m: Any, fingerprint_m: Any, rule_m: Any) -> None:
    """Render human-readable status dashboard."""
    click.echo("Wardline Regime Status")
    click.echo("\u2500" * 22)
    click.echo()

    click.echo(f"Governance profile:    {manifest_m.governance_profile}")
    click.echo(f"Analysis level:        {manifest_m.analysis_level}")
    click.echo(f"Manifest version:      {manifest_m.schema_version}")
    click.echo()

    disabled_count = len(rule_m.disabled_rules)
    click.echo(
        f"Rules:                 {rule_m.active_rules} active, "
        f"{disabled_count} disabled"
    )
    click.echo("Coherence:             not run (use `wardline manifest coherence`)")
    click.echo()

    # Exceptions section
    click.echo("Exceptions:")
    click.echo(f"  Active:              {exception_m.active}")
    click.echo(f"  Expired:             {exception_m.expired}")
    if exception_m.total > 0:
        agent_pct = (
            (exception_m.agent_originated / exception_m.total) * 100
            if exception_m.total
            else 0.0
        )
        click.echo(
            f"  Agent-originated:    {exception_m.agent_originated} "
            f"({agent_pct:.1f}%)"
        )
    else:
        click.echo(f"  Agent-originated:    {exception_m.agent_originated}")
    click.echo(
        f"  Expedited ratio:     {exception_m.expedited_ratio * 100:.1f}% "
        f"(threshold: 15.0%)"
    )

    # Governance paths
    std_count = sum(1 for p in exception_m.governance_paths if p == "standard")
    exp_count = sum(1 for p in exception_m.governance_paths if p == "expedited")
    click.echo(
        f"  Governance paths:    {std_count} standard, {exp_count} expedited"
    )
    click.echo()

    # Fingerprint section
    click.echo("Fingerprint baseline:")
    if fingerprint_m.present:
        gen_date = fingerprint_m.generated_at[:10] if fingerprint_m.generated_at else "unknown"
        click.echo(f"  Status:              present (updated {gen_date})")
        if fingerprint_m.total > 0:
            cov_pct = fingerprint_m.coverage_ratio * 100
            click.echo(
                f"  Coverage:            {fingerprint_m.annotated}/{fingerprint_m.total} "
                f"functions ({cov_pct:.1f}%)"
            )
        else:
            click.echo("  Coverage:            0/0 functions")
    else:
        click.echo(
            "  Status:              not present (run wardline fingerprint update)"
        )
    click.echo()

    # Ratification section
    click.echo("Manifest ratification:")
    if manifest_m.ratification_date:
        click.echo(f"  Last ratified:       {manifest_m.ratification_date}")
        age_str = (
            f"{manifest_m.ratification_age_days} days"
            if manifest_m.ratification_age_days is not None
            else "unknown"
        )
        interval_str = (
            f"{manifest_m.review_interval_days} days"
            if manifest_m.review_interval_days is not None
            else "not set"
        )
        click.echo(
            f"  Ratification age:    {age_str} (interval: {interval_str})"
        )
        overdue_str = "yes" if manifest_m.ratification_overdue else "no"
        click.echo(f"  Overdue:             {overdue_str}")
    else:
        click.echo("  Last ratified:       not set")

    click.echo()
    click.echo("To gate on governance health, use: wardline regime verify --gate")


def _status_json(manifest_m: Any, exception_m: Any, fingerprint_m: Any, rule_m: Any) -> None:
    """Render JSON status output."""
    data = {
        "governance_profile": manifest_m.governance_profile,
        "analysis_level": manifest_m.analysis_level,
        "manifest_version": manifest_m.schema_version,
        "rules": {
            "active": rule_m.active_rules,
            "disabled": len(rule_m.disabled_rules),
            "disabled_rules": list(rule_m.disabled_rules),
            "disabled_unconditional": list(rule_m.disabled_unconditional),
        },
        "exception_counts": {
            "total": exception_m.total,
            "active": exception_m.active,
            "expired": exception_m.expired,
            "agent_originated": exception_m.agent_originated,
            "expedited": exception_m.expedited,
        },
        "expedited_ratio": exception_m.expedited_ratio,
        "fingerprint_coverage": {
            "present": fingerprint_m.present,
            "generated_at": fingerprint_m.generated_at,
            "age_days": fingerprint_m.age_days,
            "annotated": fingerprint_m.annotated,
            "total": fingerprint_m.total,
            "coverage_ratio": fingerprint_m.coverage_ratio,
        },
        "ratification_date": manifest_m.ratification_date,
        "ratification_age_days": manifest_m.ratification_age_days,
        "review_interval_days": manifest_m.review_interval_days,
        "ratification_overdue": manifest_m.ratification_overdue,
    }
    click.echo(json_mod.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# regime verify
# ---------------------------------------------------------------------------


@regime.command()
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
    help="Exit 1 if any ERROR-level checks fail (combine with --strict to include WARNINGs).",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="With --gate, also exit 1 on WARNING-level failures.",
)
def verify(
    manifest_file: str,
    scan_path: str,
    output_json: bool,
    gate: bool,
    strict: bool,
) -> None:
    """Run active governance verification checks."""
    import yaml

    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.manifest.regime import (
        collect_exception_metrics,
        collect_fingerprint_metrics,
        collect_manifest_metrics,
        collect_rule_metrics,
    )

    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_file} — direct law applies")
        sys.exit(EXIT_DIRECT_LAW)

    manifest_dir = manifest_path.parent
    config_path = manifest_dir / "wardline.toml"

    # --- Collect all checks ---
    checks: list[dict[str, Any]] = []

    # Check 1: Manifest loads — if not, direct law applies (exit 3)
    manifest_load_ok = True
    try:
        load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError, OSError) as exc:
        manifest_load_ok = False
        cli_error(f"manifest invalid: {exc} — direct law applies")
        sys.exit(EXIT_DIRECT_LAW)

    if manifest_load_ok:
        checks.append({
            "check": "manifest_loads",
            "passed": True,
            "severity": "ERROR",
            "evidence": "Manifest loaded successfully.",
        })

    # Check 2: Coherence checks pass (run inline)
    if manifest_load_ok:
        coherence_issues, coherence_err = _run_coherence_checks(
            manifest_path, Path(scan_path)
        )
        if coherence_err:
            checks.append({
                "check": "coherence_checks",
                "passed": False,
                "severity": "ERROR",
                "evidence": f"Coherence load error: {coherence_err}",
            })
        else:
            has_error_issues = any(
                _COHERENCE_SEVERITY_MAP.get(i.kind) == "ERROR"
                for i in coherence_issues
            )
            if has_error_issues:
                error_kinds = [
                    i.kind
                    for i in coherence_issues
                    if _COHERENCE_SEVERITY_MAP.get(i.kind) == "ERROR"
                ]
                checks.append({
                    "check": "coherence_checks",
                    "passed": False,
                    "severity": "ERROR",
                    "evidence": (
                        f"{len(error_kinds)} error-level coherence issue(s): "
                        f"{', '.join(error_kinds)}"
                    ),
                })
            else:
                warning_count = len(coherence_issues)
                checks.append({
                    "check": "coherence_checks",
                    "passed": True,
                    "severity": "ERROR",
                    "evidence": (
                        f"No error-level coherence issues ({warning_count} warning(s))."
                    ),
                })

    # Check 3: No disabled UNCONDITIONAL rules
    rule_m = collect_rule_metrics(manifest_path, config_path)
    if rule_m.disabled_unconditional:
        checks.append({
            "check": "no_disabled_unconditional",
            "passed": False,
            "severity": "ERROR",
            "evidence": (
                f"Disabled UNCONDITIONAL rules: "
                f"{', '.join(rule_m.disabled_unconditional)}"
            ),
        })
    else:
        checks.append({
            "check": "no_disabled_unconditional",
            "passed": True,
            "severity": "ERROR",
            "evidence": "All UNCONDITIONAL rules active.",
        })

    # Check 4: Exception register valid (schema validates, no UNCONDITIONAL targets)
    exception_valid = True
    try:
        from wardline.manifest.exceptions import load_exceptions

        load_exceptions(manifest_dir)
    except Exception as exc:
        exception_valid = False
        checks.append({
            "check": "exception_register_valid",
            "passed": False,
            "severity": "ERROR",
            "evidence": f"Exception register invalid: {exc}",
        })

    if exception_valid:
        checks.append({
            "check": "exception_register_valid",
            "passed": True,
            "severity": "ERROR",
            "evidence": "Exception register schema valid, no UNCONDITIONAL targets.",
        })

    # Collect metrics for remaining checks
    exception_m = collect_exception_metrics(manifest_dir)
    fingerprint_m = collect_fingerprint_metrics(manifest_dir)
    manifest_m = collect_manifest_metrics(manifest_path)

    # Check 5: Expedited ratio below threshold (15%)
    threshold = 0.15
    if exception_m.expedited_ratio >= threshold:
        checks.append({
            "check": "expedited_ratio",
            "passed": False,
            "severity": "WARNING",
            "evidence": (
                f"Expedited ratio {exception_m.expedited_ratio * 100:.1f}% "
                f"exceeds threshold {threshold * 100:.1f}%."
            ),
        })
    else:
        checks.append({
            "check": "expedited_ratio",
            "passed": True,
            "severity": "WARNING",
            "evidence": (
                f"Expedited ratio {exception_m.expedited_ratio * 100:.1f}% "
                f"below threshold {threshold * 100:.1f}%."
            ),
        })

    # Check 6: Fingerprint baseline exists
    if fingerprint_m.present:
        checks.append({
            "check": "fingerprint_baseline_exists",
            "passed": True,
            "severity": "WARNING",
            "evidence": f"Baseline present (generated {fingerprint_m.generated_at}).",
        })
    else:
        checks.append({
            "check": "fingerprint_baseline_exists",
            "passed": False,
            "severity": "WARNING",
            "evidence": "Fingerprint baseline not present.",
        })

    # Check 7: Fingerprint baseline fresh (age < ratification interval)
    if fingerprint_m.present and manifest_m.review_interval_days is not None:
        if (
            fingerprint_m.age_days is not None
            and fingerprint_m.age_days >= manifest_m.review_interval_days
        ):
            checks.append({
                "check": "fingerprint_baseline_fresh",
                "passed": False,
                "severity": "WARNING",
                "evidence": (
                    f"Baseline age {fingerprint_m.age_days} days "
                    f">= interval {manifest_m.review_interval_days} days."
                ),
            })
        else:
            age = fingerprint_m.age_days if fingerprint_m.age_days is not None else 0
            checks.append({
                "check": "fingerprint_baseline_fresh",
                "passed": True,
                "severity": "WARNING",
                "evidence": (
                    f"Baseline age {age} days "
                    f"< interval {manifest_m.review_interval_days} days."
                ),
            })
    elif not fingerprint_m.present:
        checks.append({
            "check": "fingerprint_baseline_fresh",
            "passed": False,
            "severity": "WARNING",
            "evidence": "No baseline to check freshness.",
        })
    else:
        checks.append({
            "check": "fingerprint_baseline_fresh",
            "passed": True,
            "severity": "WARNING",
            "evidence": "No review interval configured; freshness check skipped.",
        })

    # Check 8: No expired exceptions
    if exception_m.expired > 0:
        checks.append({
            "check": "no_expired_exceptions",
            "passed": False,
            "severity": "WARNING",
            "evidence": f"{exception_m.expired} expired exception(s).",
        })
    else:
        checks.append({
            "check": "no_expired_exceptions",
            "passed": True,
            "severity": "WARNING",
            "evidence": "No expired exceptions.",
        })

    # Check 9: Manifest ratification current
    if manifest_m.ratification_overdue:
        checks.append({
            "check": "ratification_current",
            "passed": False,
            "severity": "WARNING",
            "evidence": (
                f"Ratification overdue: age {manifest_m.ratification_age_days} days "
                f">= interval {manifest_m.review_interval_days} days."
            ),
        })
    else:
        checks.append({
            "check": "ratification_current",
            "passed": True,
            "severity": "WARNING",
            "evidence": "Manifest ratification current.",
        })

    # Check 10: Ratification metadata present (MAN-007)
    has_ratification = (
        manifest_m.ratified_by_present
        and manifest_m.ratification_date is not None
        and manifest_m.review_interval_days is not None
    )
    if has_ratification:
        checks.append({
            "check": "ratification_metadata_present",
            "passed": True,
            "severity": "ERROR",
            "evidence": "Ratification authority, date, and review interval declared.",
        })
    else:
        missing = []
        if not manifest_m.ratified_by_present:
            missing.append("ratified_by")
        if manifest_m.ratification_date is None:
            missing.append("ratification_date")
        if manifest_m.review_interval_days is None:
            missing.append("review_interval_days")
        checks.append({
            "check": "ratification_metadata_present",
            "passed": False,
            "severity": "ERROR",
            "evidence": f"Missing ratification metadata: {', '.join(missing)}.",
        })

    # Check 11: Temporal separation declared (MAN-011)
    ts = manifest_m.temporal_separation_posture
    governance_profile = manifest_m.governance_profile
    if governance_profile == "lite":
        if ts is not None:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": True,
                "severity": "WARNING",
                "evidence": f"Temporal separation posture declared: {ts}.",
            })
        else:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": False,
                "severity": "WARNING",
                "evidence": (
                    "Temporal separation posture not declared. "
                    "Assessor cannot determine whether enforced or "
                    "alternative applies. Add temporal_separation to "
                    "manifest metadata."
                ),
            })
    else:
        if ts is not None and ts.startswith("alternative:"):
            checks.append({
                "check": "temporal_separation_declared",
                "passed": False,
                "severity": "ERROR",
                "evidence": (
                    "Assurance profile does not permit temporal "
                    "separation alternatives."
                ),
            })
        else:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": ts == "enforced",
                "severity": "ERROR",
                "evidence": (
                    "Temporal separation enforced."
                    if ts == "enforced"
                    else "Temporal separation posture not declared."
                ),
            })

    # Check 12: Annotation change tracking (MAN-010)
    # This repo's chosen Lite evidence: fingerprint baseline exists + CODEOWNERS.
    fingerprint_path = manifest_dir / "wardline.fingerprint.json"
    if fingerprint_path.exists():
        checks.append({
            "check": "annotation_change_tracking",
            "passed": True,
            "severity": "WARNING",
            "evidence": "Fingerprint baseline present — annotation changes visible in diffs.",
        })
    else:
        checks.append({
            "check": "annotation_change_tracking",
            "passed": False,
            "severity": "WARNING",
            "evidence": (
                "No fingerprint baseline found. Run 'wardline fingerprint update' "
                "to establish annotation change tracking."
            ),
        })

    # --- Format output ---
    if output_json:
        _verify_json(checks)
    else:
        _verify_text(checks)

    # --- Gate logic ---
    if gate:
        gate_severities = {"ERROR"}
        if strict:
            gate_severities.add("WARNING")
        has_gate_failures = any(
            not c["passed"] and c["severity"] in gate_severities for c in checks
        )
        if has_gate_failures:
            sys.exit(1)


def _verify_text(checks: list[dict[str, Any]]) -> None:
    """Render human-readable verify output."""
    passed_count = sum(1 for c in checks if c["passed"])
    failed_count = sum(1 for c in checks if not c["passed"])
    error_failures = sum(
        1 for c in checks if not c["passed"] and c["severity"] == "ERROR"
    )
    warning_failures = sum(
        1 for c in checks if not c["passed"] and c["severity"] == "WARNING"
    )

    click.echo("Wardline Regime Verify")
    click.echo("\u2500" * 22)
    click.echo()

    for check in checks:
        status_icon = "PASS" if check["passed"] else "FAIL"
        severity = check["severity"]
        click.echo(f"  [{status_icon}] [{severity}] {check['check']}")
        click.echo(f"         {check['evidence']}")

    click.echo()
    click.echo(
        f"{len(checks)} checks: {passed_count} passed, {failed_count} failed "
        f"({error_failures} error(s), {warning_failures} warning(s))"
    )


def _verify_json(checks: list[dict[str, Any]]) -> None:
    """Render JSON verify output."""
    click.echo(json_mod.dumps({"checks": checks}, indent=2))
