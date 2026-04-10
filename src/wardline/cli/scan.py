"""wardline scan — full pipeline CLI command.

Wires manifest loading, config parsing, registry sync, rule
execution, GOVERNANCE signals, and SARIF output into a single
``wardline scan <path>`` command.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from wardline.cli._gate import count_gate_blocking, severity_breakdown
from wardline.cli._helpers import cli_error
from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding, make_governance_finding
from wardline.scanner.rules import make_rules
from wardline.scanner.sarif import _PSEUDO_RULE_IDS, SarifReport

if TYPE_CHECKING:
    from collections.abc import Sequence

    from wardline.manifest.models import BoundaryEntry as _BoundaryEntry
    from wardline.manifest.models import ScannerConfig, WardlineManifest
    from wardline.scanner.rules.base import RuleBase

logger = logging.getLogger("wardline")


class _ConfigError:
    """Sentinel for config loading failure."""


_CONFIG_ERROR = _ConfigError()

# Exit codes (shared with main.py)
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CONFIG_ERROR = 2
# Exit code 3 is reserved for regime direct law — NOT used by scan.
# TOOL_ERROR findings exit 1 (EXIT_FINDINGS) like any other finding.




def _compute_deferred_fix_ratio(
    active_count: int,
    deferred_count: int,
) -> float | None:
    """Compute deferredFixRatio from active exception counts.

    Returns 0.0 when no active exceptions exist (nothing to defer).
    Returns None when active exceptions exist but none have
    elimination_path (unclassified). Returns the ratio when at
    least one has elimination_path.
    """
    if active_count == 0:
        return 0.0  # no exceptions at all → zero deferred fixes
    if deferred_count == 0:
        return None  # unclassified — distinct from 0.0
    return deferred_count / active_count


def _compute_manifest_hash(manifest_path: Path) -> str | None:
    """SHA-256 of root manifest raw bytes only (§10.1).

    The spec defines wardline.manifestHash as the hash of the root manifest
    file content — not a combined hash with overlays. Overlay hashes are
    reported separately via wardline.overlayHashes.
    """
    import hashlib

    try:
        raw = manifest_path.read_bytes()
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    except OSError:
        return None


def _compute_input_hash(
    file_paths: Sequence[Path], project_root: Path
) -> tuple[str, int]:
    """Hash-of-hashes over analysed files (§10.1 algorithm).

    Args:
        file_paths: Files the engine analysed (from ScanResult.scanned_file_paths).
        project_root: The project root (manifest_path.parent), NOT the scan
            target path. The spec requires paths relative to project root so
            that scanning a subdirectory produces the same inputHash as scanning
            the full project (for the same file set).

    Returns:
        (hash_string, deduplicated_file_count). The hash is always valid
        (including for empty file sets). OSError on any file is re-raised —
        silently skipping would make the hash describe a different set than
        the scan consumed.
    """
    import hashlib

    resolved_root = project_root.resolve()

    # Deduplicate after symlink resolution (§10.1 step 2)
    seen: dict[Path, None] = {}
    for fp in file_paths:
        resolved = fp.resolve()
        if resolved not in seen:
            seen[resolved] = None

    records: list[str] = []
    for resolved in seen:
        # Step 3: normalize to forward-slash path relative to project root
        try:
            rel = resolved.relative_to(resolved_root)
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        # Step 4: SHA-256 of raw bytes (OSError re-raises — hard failure)
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        # Step 5: form record
        records.append(f"{normalized}\x00{digest}")

    # Step 6: sort, concatenate with \n terminators, hash
    records.sort()
    combined = "".join(r + "\n" for r in records)
    return (
        "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        len(records),
    )


def _compute_overlay_hashes(
    consumed_overlay_paths: Sequence[Path],
    project_root: Path,
) -> tuple[str, ...]:
    """SHA-256 of each consumed overlay, sorted by normalized path (§10.1).

    Symlinked overlay files are excluded (consistent with overlay discovery).
    """
    import hashlib

    entries: list[tuple[str, str]] = []
    resolved_root = project_root.resolve()
    for overlay_path in consumed_overlay_paths:
        if overlay_path.is_symlink():
            continue
        resolved = overlay_path.resolve()
        try:
            rel = resolved.relative_to(resolved_root)
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        entries.append((normalized, f"sha256:{digest}"))

    entries.sort(key=lambda e: e[0])
    return tuple(h for _, h in entries)


def _read_coverage_ratio(manifest_path: Path) -> float | None:
    """Read annotation coverage ratio from fingerprint baseline.

    Returns None when no baseline exists (property omitted from SARIF).
    Returns 0.0 when baseline exists but shows zero coverage.
    """
    import json

    baseline = manifest_path.parent / "wardline.fingerprint.json"
    if not baseline.exists():
        return None
    try:
        data = json.loads(baseline.read_text(encoding="utf-8"))
        ratio = data.get("coverage", {}).get("ratio")
        return float(ratio) if ratio is not None else None
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _resolve_coverage_ratio(
    baseline_ratio: float | None,
    annotated_count: int,
    total_count: int,
) -> tuple[float | None, float | None]:
    """Resolve coverage ratio from baseline and scan-time sources.

    Returns ``(coverage_ratio, scan_time_ratio)`` where *coverage_ratio*
    is the best available value (baseline preferred) and *scan_time_ratio*
    is the ratio computed from annotation counts (``None`` when
    *total_count* is zero).
    """
    scan_time: float | None = None
    if total_count > 0:
        scan_time = annotated_count / total_count
    resolved = baseline_ratio if baseline_ratio is not None else scan_time
    return resolved, scan_time


def _read_conformance_gaps(
    manifest_path: Path, scan_path: Path | None = None
) -> tuple[str, ...]:
    """Read conformance gaps from wardline.conformance.json.

    Returns gap strings from the generated conformance status file.
    If the file is absent or stale, returns a gap describing that.

    Args:
        manifest_path: Path to wardline.yaml.
        scan_path: Resolved scan target path. When provided and it overlaps
            the self-hosting source path, self_hosting_input_hash is also
            validated for staleness.
    """
    import json

    conf_path = manifest_path.parent / "wardline.conformance.json"
    if not conf_path.exists():
        return ("conformance status not generated — run 'wardline corpus publish'",)

    try:
        data = json.loads(conf_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ("conformance status file unreadable",)

    # Staleness check: compare input identities against current state
    import wardline as _pkg
    inputs = data.get("inputs", {})

    stale_reasons: list[str] = []
    if inputs.get("tool_version") != _pkg.__version__:
        stale_reasons.append("tool_version")
    manifest_hash = _compute_manifest_hash(manifest_path)
    if manifest_hash is not None and inputs.get("manifest_hash") != manifest_hash:
        stale_reasons.append("manifest_hash")
    # commit_ref: validated against HEAD, not the scan target's inputHash
    current_ref = _git_head_ref()
    if current_ref is not None and inputs.get("commit_ref", "unknown") != current_ref:
        stale_reasons.append("commit_ref")
    # corpus_hash: validated against the current corpus on disk
    corpus_dir = manifest_path.parent / "corpus"
    if corpus_dir.is_dir() and "corpus_hash" in inputs:
        from wardline.cli.corpus_cmds import _compute_corpus_hash
        current_corpus_hash = _compute_corpus_hash(corpus_dir)
        if inputs["corpus_hash"] != current_corpus_hash:
            stale_reasons.append("corpus_hash")
    # self_hosting_input_hash: validated by hashing the self-hosting source
    # files on disk and comparing against the conformance file's recorded
    # hash. This catches source file changes even when commit_ref is
    # unavailable (e.g., not in a git repo, or dirty working tree).
    if "self_hosting_input_hash" in inputs:
        self_hosting_dir = manifest_path.parent / "src" / "wardline"
        if self_hosting_dir.is_dir():
            py_files = sorted(self_hosting_dir.rglob("*.py"))
            if py_files:
                current_sh_hash, _ = _compute_input_hash(
                    py_files, manifest_path.parent
                )
                if inputs["self_hosting_input_hash"] != current_sh_hash:
                    stale_reasons.append("self_hosting_input_hash")
    # The self_hosting_input_hash is primarily useful for corpus publish's
    # own evidence chain, not for scan-time re-validation.

    if stale_reasons:
        return (
            f"conformance status stale — {', '.join(stale_reasons)} changed",
            *tuple(data.get("gaps", [])),
        )

    return tuple(data.get("gaps", []))


def _utc_timestamp() -> str:
    """ISO 8601 UTC timestamp for scan temporal binding."""
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def _git_head_ref() -> str | None:
    """Git HEAD commit hash, or None if not in a git repo."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            head = result.stdout.strip()
            # Check if working tree is dirty
            try:
                dirty_check = subprocess.run(
                    ["git", "diff-index", "--quiet", "HEAD"],
                    capture_output=True,
                    timeout=5,
                )
                if dirty_check.returncode != 0:
                    return head + "-dirty"
            except (OSError, subprocess.TimeoutExpired):
                pass
            return head
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _canonical_registry() -> frozenset[RuleId]:
    """Return the set of canonical (non-pseudo) rule IDs from the registry."""
    return frozenset(r for r in RuleId if r not in _PSEUDO_RULE_IDS)


def _check_registry_sync(
    rules: tuple[RuleBase, ...],
) -> list[str]:
    """Bidirectional registry sync check.

    Returns a list of mismatch descriptions (empty = clean).
    - Every canonical RuleId must have a loaded rule class.
    - Every loaded rule class must have a canonical RuleId.
    """
    registry = _canonical_registry()
    loaded_ids = frozenset(r.RULE_ID for r in rules)

    mismatches: list[str] = []

    in_registry_not_loaded = registry - loaded_ids
    if in_registry_not_loaded:
        for rid in sorted(in_registry_not_loaded, key=str):
            mismatches.append(f"registry has {rid} but no rule class is loaded")

    in_loaded_not_registry = loaded_ids - registry
    if in_loaded_not_registry:
        for rid in sorted(in_loaded_not_registry, key=str):
            mismatches.append(
                f"rule class loaded for {rid} but not in registry"
            )

    return mismatches


def _make_governance_finding(
    rule_id: RuleId,
    message: str,
    severity: Severity = Severity.WARNING,
) -> Finding:
    """Create a GOVERNANCE-level diagnostic finding (delegates to shared factory)."""
    return make_governance_finding(rule_id, message, severity=severity)


def _disabled_rule_findings(
    disabled_rules: tuple[RuleId, ...],
    all_rules: tuple[RuleBase, ...],
) -> list[Finding]:
    """Emit GOVERNANCE findings for disabled rules.

    WARNING for standard disablement; ERROR for UNCONDITIONAL rules.
    A rule is UNCONDITIONAL if its DEFAULT_EXCEPTIONABILITY is
    UNCONDITIONAL (meaning all its findings are non-exceptable).
    """
    findings: list[Finding] = []
    # Build set of rules whose default exceptionability is UNCONDITIONAL
    unconditional_ids = frozenset(
        r.RULE_ID for r in all_rules
        if getattr(r, "DEFAULT_EXCEPTIONABILITY", Exceptionability.STANDARD)
        == Exceptionability.UNCONDITIONAL
    )

    for rid in disabled_rules:
        if rid in unconditional_ids:
            severity = Severity.ERROR
            msg = (
                f"UNCONDITIONAL rule {rid} has been disabled "
                "by configuration"
            )
        else:
            severity = Severity.WARNING
            msg = f"Rule {rid} has been disabled by configuration"

        findings.append(
            _make_governance_finding(
                RuleId.GOVERNANCE_RULE_DISABLED,
                msg,
                severity=severity,
            )
        )
    return findings


def _effective_known_validators(
    cfg: ScannerConfig | None,
) -> frozenset[str]:
    """Return the effective known_validators set after config merging."""
    from wardline.scanner.rejection_path import BUILTIN_KNOWN_VALIDATORS

    if cfg is None:
        return BUILTIN_KNOWN_VALIDATORS
    if cfg.known_validators is not None:
        return frozenset(cfg.known_validators)
    if cfg.known_validators_extra:
        return BUILTIN_KNOWN_VALIDATORS | frozenset(cfg.known_validators_extra)
    return BUILTIN_KNOWN_VALIDATORS


def _custom_known_validator_findings(
    effective_known_validators: frozenset[str],
) -> list[Finding]:
    """Emit GOVERNANCE findings for non-built-in known_validators entries."""
    from wardline.scanner.rejection_path import BUILTIN_KNOWN_VALIDATORS

    custom_entries = sorted(effective_known_validators - BUILTIN_KNOWN_VALIDATORS)
    return [
        _make_governance_finding(
            RuleId.GOVERNANCE_CUSTOM_KNOWN_VALIDATOR,
            f"Custom known_validators entry active: {entry}",
            severity=Severity.WARNING,
        )
        for entry in custom_entries
    ]


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=None,
              help="Path to wardline.yaml manifest.")
@click.option("--config", type=click.Path(exists=False), default=None,
              help="Path to wardline.toml config.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (stdout if not given).")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging to stderr.")
@click.option("--debug", is_flag=True, help="Debug logging to stderr.")
@click.option("--verification-mode", is_flag=True,
              help="Deterministic output (no timestamps).")
@click.option("--max-unknown-raw-percent", type=float, default=None,
              help="Max percentage of UNKNOWN_RAW findings per file scanned "
                   "(exit 1 if exceeded). Denominator is files_scanned.")
@click.option("--allow-registry-mismatch", is_flag=True, default=False,
              help="Emit GOVERNANCE finding instead of exit 2 on registry mismatch.")
@click.option("--allow-permissive-distribution", is_flag=True, default=False,
              help="Emit GOVERNANCE finding for permissive distribution mode.")
@click.option("--preview-phase2", is_flag=True, default=False,
              help="Output Phase 2 migration impact report (JSON) instead of SARIF.")
@click.option("--resolved", default=None, type=click.Path(exists=True),
              help="Pre-resolved manifest (wardline.resolved.json)")
@click.option("--allow-stale-resolved", is_flag=True, default=False,
              help="Warn instead of exit 2 when resolved file's manifest hash is stale.")
@click.option("--strict-governance", is_flag=True, default=False,
              help="Treat GOVERNANCE findings as scan failures (exit 1).")
@click.option("--retrospective", default=None, type=str,
              help="Retrospective scan for degraded-law window (commit range, e.g. abc123..def456).")
@click.option("--changed-only", is_flag=True, default=False,
              help="Only scan files changed since HEAD (requires git).")
@click.option("--compare", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Baseline SARIF file to compare against (reports new/resolved findings).")
def scan(
    path: str,
    manifest: str | None,
    config: str | None,
    output: str | None,
    verbose: bool,
    debug: bool,
    verification_mode: bool,
    max_unknown_raw_percent: float | None,
    allow_registry_mismatch: bool,
    allow_permissive_distribution: bool,
    preview_phase2: bool,
    resolved: str | None,
    allow_stale_resolved: bool,
    strict_governance: bool,
    retrospective: str | None,
    changed_only: bool,
    compare: str | None,
) -> None:
    """Scan Python files for boundary violations."""
    cli_handler = _setup_logging(verbose=verbose, debug=debug)
    click.get_current_context().call_on_close(lambda: _teardown_logging(cli_handler))

    # --- Load manifest ---
    _manifest_result = _load_manifest(manifest, Path(path).resolve())
    if _manifest_result is None:
        sys.exit(EXIT_CONFIG_ERROR)
    manifest_model, manifest_path = _manifest_result

    # --- Load optional config ---
    cfg = _load_config(config)
    if cfg is _CONFIG_ERROR:
        sys.exit(EXIT_CONFIG_ERROR)
    assert not isinstance(cfg, _ConfigError)  # narrow type for mypy

    # --- Merge CLI flags with config (CLI wins) ---
    effective_max_pct = max_unknown_raw_percent
    effective_allow_mismatch = allow_registry_mismatch
    effective_allow_permissive = allow_permissive_distribution
    effective_strict_governance = strict_governance

    if cfg is not None:
        if effective_max_pct is None:
            effective_max_pct = cfg.max_unknown_raw_percent
        if not effective_allow_mismatch:
            effective_allow_mismatch = cfg.allow_registry_mismatch
        if not effective_allow_permissive:
            effective_allow_permissive = cfg.allow_permissive_distribution
        if not effective_strict_governance:
            effective_strict_governance = cfg.strict_governance

    # --- Create rules ---
    all_rules = make_rules()

    # --- Filter out disabled rules ---
    disabled_rules: tuple[RuleId, ...] = ()
    if cfg is not None and cfg.disabled_rules:
        disabled_rules = cfg.disabled_rules

    active_rules = tuple(
        r for r in all_rules if r.RULE_ID not in disabled_rules
    )

    # --- Registry sync check ---
    mismatches = _check_registry_sync(all_rules)
    governance_findings: list[Finding] = []

    if mismatches:
        if effective_allow_mismatch:
            for mm in mismatches:
                governance_findings.append(
                    _make_governance_finding(
                        RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED,
                        f"Registry mismatch (allowed): {mm}",
                    )
                )
            logger.warning(
                "Registry mismatch allowed: %d mismatch(es)", len(mismatches)
            )
        else:
            for mm in mismatches:
                cli_error(f"registry sync failed: {mm}")
            sys.exit(EXIT_CONFIG_ERROR)

    # --- GOVERNANCE: disabled rules ---
    governance_findings.extend(
        _disabled_rule_findings(disabled_rules, all_rules)
    )

    # --- GOVERNANCE: permissive distribution ---
    if effective_allow_permissive:
        governance_findings.append(
            _make_governance_finding(
                RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION,
                "Permissive distribution mode is active",
            )
        )

    effective_known_validators = _effective_known_validators(cfg)
    governance_findings.extend(
        _custom_known_validator_findings(effective_known_validators)
    )

    # --- Determine target paths ---
    scan_path = Path(path).resolve()
    target_paths = cfg.target_paths if cfg is not None and cfg.target_paths else (scan_path,)

    exclude_paths: tuple[Path, ...] = ()
    if cfg is not None and cfg.exclude_paths:
        exclude_paths = cfg.exclude_paths

    # --- Resolve overlay boundaries ---
    boundaries: tuple[_BoundaryEntry, ...] = ()
    optional_fields: tuple[object, ...] = ()
    resolved_rule_overrides: tuple[dict[str, object], ...] | None = None
    consumed_overlay_paths: tuple[Path, ...] = ()

    if resolved:
        loaded = _load_resolved(
            resolved, manifest_path,
            manifest_model=manifest_model,
            allow_stale=allow_stale_resolved,
        )
        if loaded is None:
            sys.exit(EXIT_CONFIG_ERROR)
        boundaries, resolved_rule_overrides, optional_fields, consumed_overlay_paths = loaded
        if resolved_rule_overrides is not None:
            import dataclasses as _dc

            from wardline.manifest.models import RulesConfig

            manifest_model = _dc.replace(
                manifest_model,
                rules=RulesConfig(overrides=resolved_rule_overrides),
            )
    else:
        from wardline.manifest.loader import ManifestPolicyError as _PolicyError
        from wardline.manifest.resolve import (
            resolve_boundaries,
            resolve_optional_fields,
        )

        # manifest_path is threaded from _load_manifest — no re-discovery needed
        try:
            boundaries, consumed_overlay_paths = resolve_boundaries(manifest_path.parent, manifest_model)
        except _PolicyError as exc:
            cli_error(str(exc))
            sys.exit(EXIT_CONFIG_ERROR)
        try:
            optional_fields = resolve_optional_fields(
                manifest_path.parent,
                manifest_model,
            )
        except _PolicyError as exc:
            cli_error(str(exc))
            sys.exit(EXIT_CONFIG_ERROR)

    # --- Resolve changed-only file set ---
    changed_file_set: frozenset[Path] | None = None
    if changed_only:
        changed_file_set = _git_changed_files(scan_path)
        if changed_file_set is None:
            cli_error("--changed-only requires a git repository")
            sys.exit(EXIT_CONFIG_ERROR)
        logger.info("Incremental scan: %d changed file(s)", len(changed_file_set))

    # --- Create engine and run scan ---
    from wardline.scanner.engine import ScanEngine, ScanResult

    analysis_level = cfg.analysis_level if cfg is not None else 1
    engine = ScanEngine(
        target_paths=target_paths,
        exclude_paths=exclude_paths,
        rules=active_rules,
        manifest=manifest_model,
        boundaries=boundaries,
        optional_fields=optional_fields,  # type: ignore[arg-type]
        analysis_level=analysis_level,
        known_validators=effective_known_validators,
        max_expansion_rounds=cfg.max_expansion_rounds if cfg is not None else 1,
        project_root=manifest_path.parent,
        changed_files=changed_file_set,
    )

    logger.info("Scanning %d target path(s)...", len(target_paths))
    result: ScanResult = engine.scan()
    logger.info(
        "Scan complete: %d files scanned, %d skipped, %d findings",
        result.files_scanned,
        result.files_skipped,
        len(result.findings),
    )

    # --- Apply exception register ---
    from wardline.manifest.exceptions import load_exceptions
    from wardline.manifest.loader import ManifestLoadError
    from wardline.scanner.exceptions import apply_exceptions

    try:
        exceptions = load_exceptions(manifest_path.parent)
    except ManifestLoadError as exc:
        cli_error(f"exception register failed: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)
    active_exception_count = 0
    stale_exception_count = 0
    expedited_exception_ratio = 0.0
    deferred_fix_ratio: float | None = 0.0  # no exceptions → 0.0; overwritten if exceptions exist

    if exceptions:
        # NOTE: taint_map is not passed here. ScanResult does not carry a
        # global taint_map, and L3 taint propagation is per-file (intra-module).
        # Taint-drift detection is available via `wardline exception preview-drift`
        # (CLI path). The scan path detects level-stale only.
        processed, governance_ex = apply_exceptions(
            result.findings, exceptions, project_root=manifest_path.parent,
            analysis_level=analysis_level,
        )
        result.findings = processed
        governance_findings.extend(governance_ex)

        # Compute exception stats for SARIF
        import datetime as _dt

        _today = _dt.date.today()
        _active = 0
        _stale = 0
        _expedited = 0
        _deferred = 0
        for _exc in exceptions:
            if _exc.expires is not None:
                try:
                    if _dt.date.fromisoformat(_exc.expires) < _today:
                        continue
                except ValueError:
                    pass
            _active += 1
            if _exc.governance_path == "expedited":
                _expedited += 1
            if _exc.elimination_path:
                _deferred += 1
        # Stale = governance findings of type GOVERNANCE_STALE_EXCEPTION
        _stale = sum(
            1 for gf in governance_ex
            if gf.rule_id == RuleId.GOVERNANCE_STALE_EXCEPTION
        )
        active_exception_count = _active
        stale_exception_count = _stale
        expedited_exception_ratio = (
            _expedited / _active if _active > 0 else 0.0
        )
        # §10.1/§13.1.3: null = unclassified, 0.0 = no deferred fixes.
        if _active > 0:
            deferred_fix_ratio = _compute_deferred_fix_ratio(_active, _deferred)

    # --- Merge governance findings ---
    all_findings = governance_findings + result.findings

    # --- Compute run-level counts ---
    from wardline.core.taints import TaintState

    unknown_raw_count = sum(
        1 for f in result.findings
        if f.taint_state == TaintState.UNKNOWN_RAW
    )
    unresolved_decorator_count = sum(
        1 for f in result.findings
        if f.rule_id == RuleId.WARDLINE_UNRESOLVED_DECORATOR
    )

    # --- Check max_unknown_raw_percent ---
    # NOTE: denominator is files_scanned, not function count. A single file
    # with multiple UNKNOWN_RAW functions can push the ratio above 100%.
    exceeded_pct = False
    if effective_max_pct is not None and result.files_scanned > 0:
        pct = (unknown_raw_count / result.files_scanned) * 100
        if pct > effective_max_pct:
            exceeded_pct = True
            logger.warning(
                "UNKNOWN_RAW percentage %.1f%% exceeds max %.1f%%",
                pct, effective_max_pct,
            )

    # --- Preview Phase 2 report ---
    if preview_phase2:
        import json

        import wardline
        from wardline.cli.preview import build_preview_report

        report = build_preview_report(
            result.findings,
            governance_findings,
            scanned_path=str(Path(path).resolve()),
            wardline_version=wardline.__version__,
        )
        report_text = json.dumps(report, indent=2) + "\n"

        if output is not None:
            try:
                Path(output).write_text(report_text, encoding="utf-8")
            except OSError as exc:
                cli_error(f"cannot write to '{output}': {exc}")
                sys.exit(EXIT_CONFIG_ERROR)
        else:
            click.echo(report_text, nl=False)

        # Normal exit code rules apply — preview changes format, not enforcement
        has_tool_error = any(
            f.rule_id == RuleId.TOOL_ERROR for f in result.findings
        )
        preview_blocking = count_gate_blocking(result.findings)
        if has_tool_error or exceeded_pct or preview_blocking > 0:
            sys.exit(EXIT_FINDINGS)
        else:
            sys.exit(EXIT_CLEAN)

    # --- Build SARIF output ---
    loaded_rule_ids = frozenset(r.RULE_ID for r in active_rules)
    manifest_hash = _compute_manifest_hash(manifest_path)
    if manifest_hash is None:
        logger.warning("Manifest hash unavailable — SARIF report has no policy binding")

    # --- Compute run identity properties (§10.1) ---
    overlay_hashes = _compute_overlay_hashes(
        consumed_overlay_paths, manifest_path.parent
    )
    baseline_coverage_ratio = _read_coverage_ratio(manifest_path)
    coverage_ratio, scan_time_coverage_ratio = _resolve_coverage_ratio(
        baseline_coverage_ratio, result.annotated_function_count, result.total_function_count,
    )
    if result.total_function_count == 0:
        logger.debug("Zero functions discovered during scan — coverage ratio unavailable")
    conformance_gaps = _read_conformance_gaps(manifest_path, scan_path=scan_path)

    # --- Compute control law (§9.5) ---
    from wardline.manifest.regime import collect_fingerprint_metrics, collect_manifest_metrics
    from wardline.scanner.sarif import compute_control_law

    manifest_metrics = collect_manifest_metrics(manifest_path)
    canonical_rule_ids = frozenset(r for r in RuleId if r not in _PSEUDO_RULE_IDS)
    disabled_rule_values = tuple(sorted(
        r.value for r in canonical_rule_ids - loaded_rule_ids
    ))

    # Read floor violation counts from conformance data
    conf_path = manifest_path.parent / "wardline.conformance.json"
    precision_violations = 0
    recall_violations = 0
    conformance_never_run = False
    conformance_data_unavailable = False

    if not conf_path.exists():
        conformance_never_run = True
        logger.warning("wardline.conformance.json not found — corpus floor violations unknown")
    else:
        import json
        try:
            _conf_data = json.loads(conf_path.read_text(encoding="utf-8"))
            if "cells_below_precision_floor" not in _conf_data or "cells_below_recall_floor" not in _conf_data:
                conformance_data_unavailable = True
                logger.warning("wardline.conformance.json missing floor violation keys — treating as unavailable")
            else:
                precision_violations = int(_conf_data["cells_below_precision_floor"])
                recall_violations = int(_conf_data["cells_below_recall_floor"])
        except (json.JSONDecodeError, OSError, ValueError, TypeError):
            conformance_data_unavailable = True
            logger.warning("wardline.conformance.json malformed — treating as unavailable")

    # Read fingerprint baseline age
    _fp_metrics = collect_fingerprint_metrics(manifest_path.parent)
    raw_age = _fp_metrics.age_days  # None when no baseline
    fingerprint_age_days: int | None = raw_age
    fingerprint_age_unknown = False
    no_fingerprint_baseline = raw_age is None

    if no_fingerprint_baseline:
        fingerprint_age_unknown = True  # No baseline → can't vouch for freshness

    # Detect initial setup: both conformance file and fingerprint baseline absent
    is_initial_setup = conformance_never_run and no_fingerprint_baseline

    control_law, control_law_degradations = compute_control_law(
        ratification_overdue=manifest_metrics.ratification_overdue,
        conformance_gaps=conformance_gaps,
        rules_disabled=disabled_rule_values,
        stale_exception_count=stale_exception_count,
        precision_floor_violations=precision_violations,
        recall_floor_violations=recall_violations,
        fingerprint_age_days=fingerprint_age_days,
        fingerprint_max_age_days=180,  # TODO: read from wardline.toml [governance] section
        fingerprint_age_unknown=fingerprint_age_unknown,
        conformance_data_unavailable=conformance_data_unavailable,
        conformance_never_run=conformance_never_run,
    )

    # inputHash — hard failure if a scanned file becomes unreadable
    project_root = manifest_path.parent
    try:
        input_hash, input_files = _compute_input_hash(
            result.scanned_file_paths, project_root
        )
    except OSError as exc:
        logger.error("inputHash computation failed: %s", exc)
        all_findings.append(
            _make_governance_finding(
                RuleId.TOOL_ERROR,
                f"inputHash computation failed — scanned file unreadable: {exc}",
                Severity.ERROR,
            )
        )
        input_hash = ""
        input_files = 0

    # --- Retrospective scan mode (§9.5) ---
    if retrospective:
        import dataclasses as _dc_retro

        all_findings = [
            _dc_retro.replace(f, retroactive_scan=True) for f in all_findings
        ]

    import wardline as _wardline_pkg

    # --- Collect governance audit events (§9 / GOV-005) ---
    from wardline.scanner.sarif import GovernanceEvent

    _gov_events: list[GovernanceEvent] = []

    # exception_expired — from stale exceptions detected during apply_exceptions
    _expired_findings = [
        gf for gf in governance_findings
        if gf.rule_id == RuleId.GOVERNANCE_STALE_EXCEPTION
    ]
    for _ef in _expired_findings:
        _gov_events.append(GovernanceEvent(
            event_type="exception_expired",
            message=_ef.message,
        ))

    # exception_escalated — from recurring exceptions (recurrence_count >= 2)
    _escalated_findings = [
        gf for gf in governance_findings
        if gf.rule_id == RuleId.GOVERNANCE_RECURRING_EXCEPTION
    ]
    for _esf in _escalated_findings:
        _gov_events.append(GovernanceEvent(
            event_type="exception_escalated",
            message=_esf.message,
        ))

    # control_law_transition — when control law is not "normal"
    if control_law != "normal":
        _gov_events.append(GovernanceEvent(
            event_type="control_law_transition",
            message=f"Control law is '{control_law}' due to: {', '.join(control_law_degradations)}",
        ))

    # ratification_renewed — when ratification is overdue
    if manifest_metrics.ratification_overdue:
        _gov_events.append(GovernanceEvent(
            event_type="ratification_renewed",
            message="Manifest ratification is overdue",
        ))

    # coverage_ratio_divergence — dual-source baseline vs scan-time divergence
    if baseline_coverage_ratio is not None and scan_time_coverage_ratio is not None:
        _divergence = abs(baseline_coverage_ratio - scan_time_coverage_ratio)
        if _divergence > 0.10:
            _gov_events.append(GovernanceEvent(
                event_type="coverage_ratio_divergence",
                message=(
                    f"Coverage ratio divergence: baseline={baseline_coverage_ratio:.4f}, "
                    f"scan={scan_time_coverage_ratio:.4f}, delta={_divergence:.4f}"
                ),
            ))

    governance_events = tuple(_gov_events)

    sarif_report = SarifReport(
        findings=all_findings,
        tool_version=_wardline_pkg.__version__,
        verification_mode=verification_mode,
        implemented_rule_ids=loaded_rule_ids,
        base_path=str(scan_path),
        unknown_raw_count=unknown_raw_count,
        unresolved_decorator_count=unresolved_decorator_count,
        files_with_degraded_taint=result.files_with_degraded_taint,
        active_exception_count=active_exception_count,
        stale_exception_count=stale_exception_count,
        expedited_exception_ratio=expedited_exception_ratio,
        deferred_fix_ratio=deferred_fix_ratio,
        governance_profile=manifest_model.governance_profile,
        analysis_level=analysis_level,
        manifest_hash=manifest_hash,
        scan_timestamp=_utc_timestamp(),
        commit_ref=_git_head_ref(),
        input_hash=input_hash,
        input_files=input_files,
        overlay_hashes=overlay_hashes,
        coverage_ratio=coverage_ratio,
        conformance_gaps=conformance_gaps,
        control_law=control_law,
        control_law_degradations=control_law_degradations,
        retroactive_scan=bool(retrospective),
        retroactive_scan_range=retrospective,
        governance_events=governance_events,
        data_paths_traced_ratio=result.call_edge_resolution_ratio,
        low_resolution_function_count=result.low_resolution_function_count,
        denominator_excluded_count=result.lambda_count,
        precision_floor_violations=precision_violations,
        recall_floor_violations=recall_violations,
        is_initial_setup=is_initial_setup,
    )

    sarif_text = sarif_report.to_json_string() + "\n"

    if output is not None:
        try:
            Path(output).write_text(sarif_text, encoding="utf-8")
        except OSError as exc:
            cli_error(f"cannot write to '{output}': {exc}")
            sys.exit(EXIT_CONFIG_ERROR)
    else:
        click.echo(sarif_text, nl=False)

    # --- Summary to stderr ---
    bd = severity_breakdown(result.findings)
    click.echo(
        f"{result.files_scanned} file(s) scanned, "
        f"{len(result.findings)} finding(s) "
        f"({bd.error_count} error, {bd.warning_count} warning, "
        f"{bd.suppress_count} suppressed"
        f"{f', {bd.excepted_count} excepted' if bd.excepted_count else ''}).",
        err=True,
    )

    # --- Baseline comparison ---
    if compare is not None:
        try:
            new_count, resolved_count = _compare_sarif_baseline(
                all_findings, compare, base_path=str(scan_path),
            )
            click.echo(
                f"{new_count} new finding(s), {resolved_count} resolved finding(s).",
                err=True,
            )
        except (OSError, KeyError, ValueError) as exc:
            cli_error(f"baseline comparison failed: {exc}")

    # --- Determine exit code ---
    # Exit code priority (highest wins):
    #   EXIT_FINDINGS   (1) — at least one unexcepted ERROR finding
    #       exists (including TOOL_ERROR), or the max_unknown_raw_percent
    #       ceiling was exceeded, or --strict-governance is set and
    #       GOVERNANCE findings exist.
    #   EXIT_CLEAN      (0) — no gate-blocking findings.
    #   (Exit code 3 is reserved for regime direct law — not used by scan.)
    #
    # The three-tier signal model (§7.3–§7.5):
    #   SUPPRESS findings are excluded (pattern is expected at this tier).
    #   WARNING findings are excluded (suspicious, non-blocking).
    #   Only ERROR findings block the gate.
    has_tool_error = any(
        f.rule_id == RuleId.TOOL_ERROR for f in all_findings
    )
    has_governance_findings = effective_strict_governance and any(
        str(f.rule_id).startswith("GOVERNANCE-") for f in all_findings
    )

    if has_tool_error or exceeded_pct or bd.gate_blocking > 0 or has_governance_findings:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)


def _compare_sarif_baseline(
    current_findings: list[Finding],
    baseline_path: str,
    base_path: str | None,
) -> tuple[int, int]:
    """Compare current findings against a baseline SARIF file.

    Returns (new_count, resolved_count). Comparison uses the composite
    key (ruleId, file, qualname).
    """
    import json

    from wardline.scanner.sarif import _normalize_artifact_uri

    def _finding_key(rule_id: str, file_uri: str, qualname: str | None) -> tuple[str, str, str]:
        return (rule_id, file_uri, qualname or "")

    # Extract keys from baseline SARIF
    baseline_data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    baseline_keys: set[tuple[str, str, str]] = set()
    for run in baseline_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            file_uri = ""
            locs = result.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file_uri = phys.get("artifactLocation", {}).get("uri", "")
            qualname = result.get("properties", {}).get("wardline.qualname", "")
            baseline_keys.add(_finding_key(rule_id, file_uri, qualname))

    # Extract keys from current findings
    current_keys: set[tuple[str, str, str]] = set()
    for f in current_findings:
        file_uri = _normalize_artifact_uri(f.file_path, base_path)
        current_keys.add(_finding_key(str(f.rule_id), file_uri, f.qualname))

    new_count = len(current_keys - baseline_keys)
    resolved_count = len(baseline_keys - current_keys)
    return new_count, resolved_count


_CLI_HANDLER_NAME = "wardline_cli"


def _setup_logging(*, verbose: bool, debug: bool) -> logging.Handler:
    """Configure logging level based on CLI flags.

    Uses a named handler so we only remove our own handler on
    re-entry, preserving any handlers installed by test harnesses
    (e.g. pytest's ``caplog`` fixture).

    Returns the installed handler so callers can pass it to
    ``_teardown_logging`` when the command completes.
    """
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    # Remove only the CLI handler we previously installed (if any),
    # leaving test-harness and library handlers intact.
    for h in logger.handlers[:]:
        if getattr(h, "name", None) == _CLI_HANDLER_NAME:
            logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler.set_name(_CLI_HANDLER_NAME)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    return handler


def _teardown_logging(handler: logging.Handler) -> None:
    """Remove the CLI handler installed by ``_setup_logging``."""
    logger.removeHandler(handler)


def _git_changed_files(repo_path: Path) -> frozenset[Path] | None:
    """Return resolved paths of files changed since HEAD, or None if not a git repo."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--diff-filter=ACMR"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    # Also include untracked .py files
    try:
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "--full-name", "*.py"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        untracked = None

    files: set[Path] = set()
    git_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if git_root_result.returncode != 0:
        return None
    git_root = Path(git_root_result.stdout.strip())

    for line in result.stdout.splitlines():
        line = line.strip()
        if line and line.endswith(".py"):
            files.add((git_root / line).resolve())

    if untracked is not None and untracked.returncode == 0:
        for line in untracked.stdout.splitlines():
            line = line.strip()
            if line:
                files.add((git_root / line).resolve())

    return frozenset(files)


def _load_manifest(
    manifest_arg: str | None,
    scan_path: Path | None = None,
) -> tuple[WardlineManifest, Path] | None:
    """Load and validate the wardline.yaml manifest.

    Returns ``(manifest, resolved_path)`` on success, or ``None`` on
    error (after printing a structured error message).
    """
    import yaml

    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    manifest_path: Path | None = None

    if manifest_arg is not None:
        manifest_path = Path(manifest_arg)
    else:
        start = scan_path if scan_path is not None else Path.cwd()
        manifest_path = discover_manifest(start)
        if manifest_path is None:
            cli_error(
                "no wardline.yaml found (searched upward from "
                f"{start})"
            )
            return None

    try:
        result = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError) as exc:
        cli_error(f"manifest schema invalid: {exc}")
        return None
    except ManifestLoadError as exc:
        cli_error(f"manifest validation failed: {exc}")
        return None

    logger.info("Loaded manifest: %s", manifest_path)
    return result, manifest_path


def _load_config(config_arg: str | None) -> ScannerConfig | None | _ConfigError:
    """Load wardline.toml scanner configuration.

    Returns:
        ScannerConfig on success, None if no config specified,
        _CONFIG_ERROR sentinel on error.
    """
    from wardline.manifest.models import ScannerConfig, ScannerConfigError

    if config_arg is None:
        return None

    config_path = Path(config_arg)
    if not config_path.exists():
        cli_error(f"config not found: {config_arg}")
        return _CONFIG_ERROR
    if config_path.is_dir():
        cli_error(f"config path is a directory, not a file: {config_arg}")
        return _CONFIG_ERROR

    try:
        return ScannerConfig.from_toml(config_path)
    except ScannerConfigError as exc:
        cli_error(f"config error: {exc}")
        return _CONFIG_ERROR
    except OSError as exc:
        cli_error(f"config load error: {exc}")
        return _CONFIG_ERROR


def _load_resolved(
    resolved_path: str,
    manifest_path: Path,
    *,
    manifest_model: WardlineManifest | None = None,
    allow_stale: bool = False,
) -> tuple[
    tuple[_BoundaryEntry, ...],
    tuple[dict[str, object], ...] | None,
    tuple[object, ...],
    tuple[Path, ...],
] | None:
    """Load boundaries, rule overrides, optional fields, and overlay paths.

    Applies the same validation pipeline as the overlay load path:
    schema validation, skip-promotion rejection, narrow-only rule-override
    validation, and duplicate boundary detection.

    Returns ``None`` on error (after printing a structured error message).
    The fourth element is the tuple of consumed overlay file paths,
    reconstructed from the resolved JSON's ``overlays_discovered`` array.
    """
    import hashlib
    import json

    from wardline.manifest.loader import ManifestPolicyError, reject_skip_promotions
    from wardline.manifest.merge import ManifestWidenError, _severity_rank
    from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry

    try:
        data = json.loads(Path(resolved_path).read_text(encoding="utf-8"))

        # F6: format_version validation
        version = data.get("format_version")
        if version != "0.2":
            cli_error(f"unsupported resolved manifest version: {version}")
            return None

        # F4: manifest_hash verification
        current_hash = "sha256:" + hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        resolved_hash = data.get("manifest_hash", "")
        if current_hash != resolved_hash:
            if allow_stale:
                click.echo(
                    "warning: resolved file is stale (manifest changed)", err=True
                )
            else:
                cli_error(
                    "resolved file is stale (manifest hash mismatch). "
                    "Re-run `wardline resolve` or pass --allow-stale-resolved."
                )
                return None

        project_root = manifest_path.parent

        raw_boundaries = data.get("boundaries", [])

        # V1: Structural validation — required fields
        for i, b in enumerate(raw_boundaries):
            if "function" not in b or "transition" not in b:
                cli_error(
                    f"resolved boundary [{i}] missing required field "
                    f"'function' or 'transition'"
                )
                return None

        # V2: Skip-promotion rejection (§13.1.2)
        reject_skip_promotions(raw_boundaries)

        # V3: Duplicate boundary detection
        seen_functions: set[str] = set()
        for b in raw_boundaries:
            fn = b["function"]
            if fn in seen_functions:
                cli_error(
                    f"resolved file contains duplicate boundary for "
                    f"function '{fn}'"
                )
                return None
            seen_functions.add(fn)

        boundaries = tuple(
            BoundaryEntry(
                function=b["function"],
                transition=b["transition"],
                from_tier=b.get("from_tier"),
                to_tier=b.get("to_tier"),
                restored_tier=b.get("restored_tier"),
                provenance=b.get("provenance"),
                validation_scope=b.get("validation_scope"),
                overlay_scope=str(
                    (project_root / b.get("overlay_scope", "")).resolve()
                ),
                overlay_path=b.get("overlay_path", ""),
            )
            for b in raw_boundaries
        )

        # V4: Rule override narrow-only validation
        raw_overrides = data.get("merged_rule_overrides")
        rule_overrides: tuple[dict[str, object], ...] | None = None
        if raw_overrides is not None:
            if manifest_model is not None:
                base_by_rule = {
                    str(ovr.get("id")): ovr
                    for ovr in manifest_model.rules.overrides
                    if isinstance(ovr.get("id"), str)
                }
                for ovr in raw_overrides:
                    rule_id = ovr.get("id")
                    if not isinstance(rule_id, str):
                        continue
                    base_ovr = base_by_rule.get(rule_id)
                    if base_ovr is None:
                        cli_error(
                            f"resolved file introduces rule override "
                            f"'{rule_id}' absent from base manifest"
                        )
                        return None
                    base_sev = base_ovr.get("severity")
                    resolved_sev = ovr.get("severity")
                    if (
                        base_sev is not None
                        and resolved_sev is not None
                        and _severity_rank(str(resolved_sev))
                        < _severity_rank(str(base_sev))
                    ):
                        cli_error(
                            f"resolved file widens severity for rule "
                            f"'{rule_id}': base={base_sev}, resolved={resolved_sev}"
                        )
                        return None
            rule_overrides = tuple(dict(ovr) for ovr in raw_overrides)

        optional_fields = tuple(
            OptionalFieldEntry(
                field=entry["field"],
                approved_default=entry["approved_default"],
                rationale=entry["rationale"],
                overlay_scope=str(
                    (project_root / entry.get("overlay_scope", "")).resolve()
                ),
                overlay_path=entry.get("overlay_path", ""),
            )
            for entry in data.get("optional_fields", [])
        )

        # V5: Overlay existence validation — verify referenced overlays still exist
        overlay_paths_list: list[Path] = []
        for entry in data.get("overlays_discovered", []):
            overlay_path = project_root / entry["path"]
            if not overlay_path.exists():
                cli_error(
                    f"resolved file references overlay '{entry['path']}' "
                    f"which no longer exists. Re-run `wardline resolve`."
                )
                return None
            overlay_paths_list.append(overlay_path)
        overlay_paths = tuple(overlay_paths_list)

        # V6: Boundary scope validation — overlay_scope must be within module_tiers
        if manifest_model is not None and manifest_model.module_tiers:
            declared_paths = {mt.path.rstrip("/") for mt in manifest_model.module_tiers}
            for b in boundaries:
                scope = b.overlay_scope
                if scope and scope != str(project_root.resolve()):
                    try:
                        rel_scope = str(Path(scope).relative_to(project_root))
                    except ValueError:
                        cli_error(
                            f"resolved boundary for '{b.function}' has overlay_scope "
                            f"'{scope}' outside project root. "
                            f"Re-run `wardline resolve`."
                        )
                        return None
                    if not any(rel_scope.startswith(dp) or dp.startswith(rel_scope) for dp in declared_paths):
                        cli_error(
                            f"resolved boundary for '{b.function}' has overlay_scope "
                            f"'{rel_scope}' outside declared module_tiers. "
                            f"Re-run `wardline resolve`."
                        )
                        return None

        return boundaries, rule_overrides, optional_fields, overlay_paths
    except ManifestPolicyError as exc:
        cli_error(f"resolved manifest policy violation: {exc}")
        return None
    except ManifestWidenError as exc:
        cli_error(f"resolved manifest policy violation: {exc}")
        return None
    except (json.JSONDecodeError, KeyError, TypeError, OSError) as exc:
        cli_error(f"resolved manifest invalid: {exc}")
        return None
