"""Manifest coherence checks — cross-reference code annotations against boundaries.

Detects multiple classes of inconsistency:
- **Orphaned annotations**: functions with wardline decorators in code but no
  matching boundary declaration in any overlay.
- **Undeclared boundaries**: overlay boundary entries whose function name does
  not appear as a decorated function in code.
- **Unmatched contracts**: validation_scope contract declarations that don't
  match any code-level annotation.
- **Stale contract bindings**: contract_bindings entries pointing to
  non-existent functions.
- **Tier-topology consistency**: tier assignments consistent with declared
  data-flow topology.
- **Missing validation_scope**: Tier 2 boundaries that require a
  validation_scope declaration but lack one.
- **Governance anomalies**: tier distribution, tier downgrades, upgrade without
  evidence, agent-originated policy changes, expired exceptions, and first-scan
  perimeter detection.
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path
    from types import MappingProxyType

    from wardline.manifest.models import (
        BoundaryEntry,
        ContractBinding,
        ExceptionEntry,
        ModuleTierEntry,
        TierEntry,
    )
    from wardline.scanner.context import WardlineAnnotation


@dataclass(frozen=True)
class CoherenceIssue:
    """A single coherence check result."""

    kind: str
    function: str
    file_path: str
    detail: str


def check_orphaned_annotations(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find decorated functions with no matching boundary declaration.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per orphaned annotation (kind
        ``"orphaned_annotation"``).
    """
    declared_functions = frozenset(b.function for b in boundaries)
    issues: list[CoherenceIssue] = []

    for (file_path, qualname), annots in sorted(annotations.items()):
        if qualname not in declared_functions:
            decorator_names = ", ".join(a.canonical_name for a in annots)
            issues.append(
                CoherenceIssue(
                    kind="orphaned_annotation",
                    function=qualname,
                    file_path=file_path,
                    detail=(
                        f"Function '{qualname}' in {file_path} has wardline "
                        f"decorators ({decorator_names}) but no boundary "
                        f"declaration in any overlay."
                    ),
                )
            )

    return issues


def check_undeclared_boundaries(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find boundary declarations with no matching decorated function in code.

    Args:
        annotations: Annotation map from ``discover_annotations``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per undeclared boundary (kind
        ``"undeclared_boundary"``).
    """
    # Collect all qualnames that have annotations
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        if boundary.function not in annotated_functions:
            issues.append(
                CoherenceIssue(
                    kind="undeclared_boundary",
                    function=boundary.function,
                    file_path="",
                    detail=(
                        f"Boundary declaration for '{boundary.function}' "
                        f"(transition: {boundary.transition}) has no matching "
                        f"wardline-decorated function in code."
                    ),
                )
            )

    return issues


# ── Governance anomaly checks ─────────────────────────────────────


def check_tier_distribution(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    *,
    max_permissive_percent: float = 60.0,
) -> list[CoherenceIssue]:
    """Check if permissive tiers (3+4) exceed the allowed threshold.

    Args:
        tiers: Tier definitions from the manifest.
        module_tiers: Module-tier assignments.
        max_permissive_percent: Maximum allowed percentage of permissive
            tiers (tier >= 3). Default 60%.

    Returns:
        A GOVERNANCE WARNING if the threshold is exceeded.
    """
    if not module_tiers or not tiers:
        return []

    # Build a map from tier id to tier number.
    # ModuleTierEntry.default_taint references TierEntry.id (same namespace).
    tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    total = len(module_tiers)
    permissive = 0
    for mt in module_tiers:
        tier_num = tier_map.get(mt.default_taint)  # default_taint is a tier id reference
        if tier_num is not None and tier_num >= 3:
            permissive += 1

    pct = (permissive / total) * 100.0
    if pct > max_permissive_percent:
        return [
            CoherenceIssue(
                kind="tier_distribution",
                function="",
                file_path="",
                detail=(
                    f"Permissive tier distribution: {pct:.1f}% of modules are "
                    f"tier 3+ (threshold: {max_permissive_percent}%)."
                ),
            )
        ]
    return []


def check_tier_downgrades(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    baseline_path: Path,
) -> list[CoherenceIssue]:
    """Detect tier downgrades compared to a baseline.

    A downgrade is when a module's tier number increases (less restrictive).

    Args:
        tiers: Current tier definitions.
        module_tiers: Current module-tier assignments.
        baseline_path: Path to ``wardline.manifest.baseline.json``.

    Returns:
        GOVERNANCE WARNING for each downgraded module, or empty list
        if the baseline file does not exist.
    """
    if not baseline_path.exists():
        return []

    try:
        baseline_data = json.loads(baseline_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logging.getLogger("wardline").warning(
            "Cannot read baseline %s: %s — skipping tier downgrade check",
            baseline_path, exc,
        )
        return []
    baseline_modules: dict[str, str] = {
        entry["path"]: entry["default_taint"]
        for entry in baseline_data.get("module_tiers", [])
    }
    baseline_tiers: dict[str, int] = {
        entry["id"]: entry["tier"]
        for entry in baseline_data.get("tiers", [])
    }

    current_tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    issues: list[CoherenceIssue] = []
    for mt in module_tiers:
        try:
            old_taint: str = baseline_modules[mt.path]
        except KeyError:
            continue  # module absent from baseline — newly introduced, skip
        old_tier = baseline_tiers.get(old_taint)
        new_tier = current_tier_map.get(mt.default_taint)
        if old_tier is not None and new_tier is not None and new_tier > old_tier:
            issues.append(
                CoherenceIssue(
                    kind="tier_downgrade",
                    function="",
                    file_path=mt.path,
                    detail=(
                        f"Tier downgrade: module '{mt.path}' changed from "
                        f"tier {old_tier} to tier {new_tier}."
                    ),
                )
            )
    return issues


def check_tier_upgrade_without_evidence(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    boundaries: tuple[BoundaryEntry, ...],
    baseline_path: Path,
) -> list[CoherenceIssue]:
    """Detect tier upgrades (stricter) without overlay boundary evidence.

    An upgrade is when a module's tier number decreases (more restrictive).
    If no boundary entry covers the upgraded module, a warning fires.

    Args:
        tiers: Current tier definitions.
        module_tiers: Current module-tier assignments.
        boundaries: All boundary entries from loaded overlays.
        baseline_path: Path to ``wardline.manifest.baseline.json``.

    Returns:
        GOVERNANCE WARNING for each upgrade without evidence.
    """
    if not baseline_path.exists():
        return []

    try:
        baseline_data = json.loads(baseline_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logging.getLogger("wardline").warning(
            "Cannot read baseline %s: %s — skipping tier upgrade check",
            baseline_path, exc,
        )
        return []
    baseline_modules: dict[str, str] = {
        entry["path"]: entry["default_taint"]
        for entry in baseline_data.get("module_tiers", [])
    }
    baseline_tiers: dict[str, int] = {
        entry["id"]: entry["tier"]
        for entry in baseline_data.get("tiers", [])
    }

    current_tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    # Collect boundary overlay scopes as evidence — these are absolute
    # paths that tell us which directory each boundary covers.
    boundary_scopes = frozenset(
        b.overlay_scope for b in boundaries if b.overlay_scope
    )

    issues: list[CoherenceIssue] = []
    for mt in module_tiers:
        try:
            old_taint: str = baseline_modules[mt.path]
        except KeyError:
            continue  # module absent from baseline — newly introduced, skip
        old_tier = baseline_tiers.get(old_taint)
        new_tier = current_tier_map.get(mt.default_taint)
        if old_tier is not None and new_tier is not None and new_tier < old_tier:
            # Check if any boundary's overlay scope covers this module path.
            # Module paths are relative (e.g. "src/wardline/scanner"),
            # overlay scopes are absolute. A scope covers a module if
            # the scope path ends with the module path.
            module_prefix = mt.path.rstrip("/")
            has_evidence = any(
                scope.endswith("/" + module_prefix)
                or scope.endswith("/" + module_prefix + "/")
                or scope == module_prefix
                for scope in boundary_scopes
            )
            if not has_evidence:
                issues.append(
                    CoherenceIssue(
                        kind="tier_upgrade_without_evidence",
                        function="",
                        file_path=mt.path,
                        detail=(
                            f"Tier upgrade without evidence: module "
                            f"'{mt.path}' changed from tier {old_tier} to "
                            f"tier {new_tier} but no overlay boundary "
                            f"covers this module."
                        ),
                    )
                )
    return issues


def check_agent_originated_exceptions(
    exceptions: tuple[ExceptionEntry, ...],
) -> list[CoherenceIssue]:
    """Detect exceptions with unknown agent provenance.

    An exception with ``agent_originated=None`` (provenance unknown) fires
    a warning. Explicit ``True`` or ``False`` values are accepted.

    Args:
        exceptions: All exception entries from the manifest.

    Returns:
        GOVERNANCE WARNING for each exception with unknown provenance.
    """
    issues: list[CoherenceIssue] = []
    for exc in exceptions:
        if exc.agent_originated is None:
            issues.append(
                CoherenceIssue(
                    kind="agent_originated_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has unknown agent provenance "
                        f"(agent_originated is null)."
                    ),
                )
            )
    return issues


def check_expired_exceptions(
    exceptions: tuple[ExceptionEntry, ...],
    *,
    max_exception_duration_days: int = 365,
    now: datetime.date | None = None,
) -> list[CoherenceIssue]:
    """Detect expired exceptions and far-future expiry dates.

    An exception fires a warning if:
    - Its ``expires`` date is in the past relative to ``now``.
    - Its ``expires`` date exceeds ``max_exception_duration_days`` from today,
      indicating a far-future expiry that circumvents the duration policy.

    Args:
        exceptions: All exception entries.
        max_exception_duration_days: Maximum allowed exception duration.
        now: Current date for clock injection (defaults to today).

    Returns:
        GOVERNANCE WARNING for each expired or far-future exception.
    """
    if now is None:
        now = datetime.date.today()

    max_expiry = now + datetime.timedelta(days=max_exception_duration_days)

    issues: list[CoherenceIssue] = []
    for exc in exceptions:
        if exc.expires is None:
            continue

        try:
            expiry_date = datetime.date.fromisoformat(exc.expires)
        except ValueError:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has invalid expires date "
                        f"'{exc.expires}' — cannot parse as ISO 8601."
                    ),
                )
            )
            continue

        if expiry_date < now:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' expired on {exc.expires}."
                    ),
                )
            )
        elif expiry_date > max_expiry:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has far-future expiry "
                        f"{exc.expires} exceeding max_exception_duration_days "
                        f"({max_exception_duration_days})."
                    ),
                )
            )

    return issues


def check_first_scan_perimeter(
    perimeter_baseline_path: Path,
) -> list[CoherenceIssue]:
    """Emit GOVERNANCE INFO when no perimeter baseline exists (first scan).

    Args:
        perimeter_baseline_path: Path to ``wardline.perimeter.baseline.json``.

    Returns:
        GOVERNANCE INFO if the baseline file does not exist.
    """
    if not perimeter_baseline_path.exists():
        return [
            CoherenceIssue(
                kind="first_scan_perimeter",
                function="",
                file_path=str(perimeter_baseline_path),
                detail=(
                    "No perimeter baseline found. This appears to be a "
                    "first scan — perimeter listing will be generated."
                ),
            )
        ]
    return []


# ── Contract and topology coherence checks ────────────────────────


def check_unmatched_contracts(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find contract declarations in validation_scopes with no matching annotation.

    For each boundary that declares a ``validation_scope`` with ``contracts``,
    verify the boundary's function has a matching annotation in code.  A
    contract declaration without a corresponding code-level annotation
    indicates a specification/implementation mismatch.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per unmatched contract (kind
        ``"unmatched_contract"``).
    """
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        if boundary.validation_scope is None:
            continue

        contracts = boundary.validation_scope.get("contracts")
        if not contracts or not isinstance(contracts, (list, tuple)):
            continue

        if boundary.function not in annotated_functions:
            _names: list[str] = []
            for _c in contracts:
                if isinstance(_c, dict):
                    try:
                        _names.append(_c["name"])
                    except KeyError:
                        _names_key = None  # contract dict has no 'name' field — skip
            contract_names = ", ".join(_names)
            issues.append(
                CoherenceIssue(
                    kind="unmatched_contract",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares contracts "
                        f"({contract_names}) in validation_scope but has no "
                        f"matching wardline-decorated function in code."
                    ),
                )
            )

    return issues


def check_stale_contract_bindings(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    contract_bindings: tuple[ContractBinding, ...],
) -> list[CoherenceIssue]:
    """Find contract_bindings entries pointing to non-existent functions.

    For each ``ContractBinding``, verify every function listed in
    ``functions`` exists as an annotated function in code.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        contract_bindings: All contract binding entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per stale binding (kind
        ``"stale_contract_binding"``).
    """
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for binding in contract_bindings:
        for func_name in binding.functions:
            if func_name not in annotated_functions:
                issues.append(
                    CoherenceIssue(
                        kind="stale_contract_binding",
                        function=func_name,
                        file_path="",
                        detail=(
                            f"Contract binding '{binding.contract}' references "
                            f"function '{func_name}' which has no wardline-"
                            f"decorated function in code."
                        ),
                    )
                )

    return issues


def check_tier_topology_consistency(
    boundaries: tuple[BoundaryEntry, ...],
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
) -> list[CoherenceIssue]:
    """Verify tier assignments are consistent with declared data-flow topology.

    For each boundary that declares ``from_tier`` and/or ``to_tier``,
    verify the referenced tier numbers actually exist in the manifest's
    tier definitions.  Also checks that ``from_tier`` corresponds to a
    module tier assignment that feeds into the boundary's scope.

    Args:
        boundaries: All boundary entries from loaded overlays.
        tiers: Tier definitions from the manifest.
        module_tiers: Module-tier assignments.

    Returns:
        One ``CoherenceIssue`` per inconsistency (kind
        ``"tier_topology_inconsistency"``).
    """
    if not tiers:
        return []

    # Build set of valid tier numbers from manifest
    valid_tier_numbers = frozenset(t.tier for t in tiers)

    # Build a map from tier id to tier number
    tier_id_to_number: dict[str, int] = {t.id: t.tier for t in tiers}

    # Build a map from module path to tier number
    module_tier_map: dict[str, int] = {}
    for mt in module_tiers:
        tier_num = tier_id_to_number.get(mt.default_taint)
        if tier_num is not None:
            module_tier_map[mt.path] = tier_num

    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        # Check from_tier references a valid tier number
        if boundary.from_tier is not None and boundary.from_tier not in valid_tier_numbers:
            issues.append(
                CoherenceIssue(
                    kind="tier_topology_inconsistency",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares from_tier="
                        f"{boundary.from_tier} which is not a valid tier "
                        f"number in the manifest (valid: "
                        f"{sorted(valid_tier_numbers)})."
                    ),
                )
            )

        # Check to_tier references a valid tier number
        if boundary.to_tier is not None and boundary.to_tier not in valid_tier_numbers:
            issues.append(
                CoherenceIssue(
                    kind="tier_topology_inconsistency",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares to_tier="
                        f"{boundary.to_tier} which is not a valid tier "
                        f"number in the manifest (valid: "
                        f"{sorted(valid_tier_numbers)})."
                    ),
                )
            )

        # Check that from_tier is consistent with the module tier feeding it.
        # The overlay_scope tells us which module this boundary lives in.
        if boundary.from_tier is not None and boundary.overlay_scope:
            for mod_path, mod_tier in module_tier_map.items():
                # Module path is relative (e.g. "src/wardline/scanner"),
                # overlay_scope is absolute.  Check if scope ends with
                # the module path.
                if (
                    boundary.overlay_scope.endswith("/" + mod_path)
                    or boundary.overlay_scope.endswith("/" + mod_path + "/")
                    or boundary.overlay_scope == mod_path
                ):
                    if mod_tier != boundary.from_tier:
                        issues.append(
                            CoherenceIssue(
                                kind="tier_topology_inconsistency",
                                function=boundary.function,
                                file_path=boundary.overlay_path,
                                detail=(
                                    f"Boundary '{boundary.function}' declares "
                                    f"from_tier={boundary.from_tier} but the "
                                    f"containing module '{mod_path}' has "
                                    f"tier {mod_tier}."
                                ),
                            )
                        )
                    break  # First match is sufficient

    return issues


def check_validation_scope_presence(
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Check that Tier 2 boundaries declare their ``validation_scope``.

    A boundary needs ``validation_scope`` when its ``transition`` is
    ``"semantic_validation"`` or ``"combined_validation"``, or when it is
    a ``"restoration"`` with semantic provenance.

    Args:
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per missing declaration (kind
        ``"missing_validation_scope"``).
    """
    issues: list[CoherenceIssue] = []
    for boundary in boundaries:
        needs_scope = boundary.transition in (
            "semantic_validation",
            "combined_validation",
        ) or (
            boundary.transition == "restoration"
            and boundary.provenance is not None
            and boundary.provenance.get("semantic") is True
        )
        if needs_scope and (
            boundary.validation_scope is None
            or not boundary.validation_scope.get("contracts")
        ):
            issues.append(
                CoherenceIssue(
                    kind="missing_validation_scope",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' claims Tier 2 semantics "
                        f"(transition={boundary.transition}) but has no "
                        f"validation_scope declaration (\u00a713.1.2)."
                    ),
                )
            )
    return issues


_UNKNOWN_FAMILY = frozenset({
    TaintState.UNKNOWN_ASSURED,
    TaintState.UNKNOWN_GUARDED,
    TaintState.UNKNOWN_RAW,
})


def check_restoration_evidence(
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Check that restoration boundaries don't overclaim their tier.

    For each boundary with ``transition == "restoration"`` and a
    non-None ``restored_tier``, compares the claimed tier against the
    maximum tier the declared evidence supports per §6.3.
    """
    from wardline.core.evidence import max_restorable_tier
    from wardline.core.tiers import TAINT_TO_TIER

    issues: list[CoherenceIssue] = []
    for boundary in boundaries:
        if boundary.transition != "restoration":
            continue
        if boundary.restored_tier is None:
            continue
        if boundary.provenance is None:
            issues.append(
                CoherenceIssue(
                    kind="insufficient_restoration_evidence",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares "
                        f"transition='restoration' with restored_tier="
                        f"{boundary.restored_tier} but has no provenance "
                        f"declaration. Restoration boundaries require "
                        f"provenance evidence (§6.3)."
                    ),
                )
            )
            continue

        structural = bool(boundary.provenance.get("structural"))
        semantic = bool(boundary.provenance.get("semantic"))
        integrity = bool(boundary.provenance.get("integrity"))
        institutional = bool(boundary.provenance.get("institutional"))

        ceiling_taint = max_restorable_tier(structural, semantic, integrity, institutional)

        # If evidence only supports an UNKNOWN-family state, no numeric tier claim
        # is valid — UNKNOWN states are outside the T1-T4 tier ladder (§6.3).
        if ceiling_taint in _UNKNOWN_FAMILY:
            issues.append(
                CoherenceIssue(
                    kind="insufficient_restoration_evidence",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' claims "
                        f"restored_tier={boundary.restored_tier} but evidence "
                        f"supports only {ceiling_taint.value} (no institutional "
                        f"provenance — numeric tier restoration requires "
                        f"institutional provenance, §6.3)."
                    ),
                )
            )
            continue

        ceiling_tier = TAINT_TO_TIER[ceiling_taint].value

        if boundary.restored_tier < ceiling_tier:
            # restored_tier uses lower=better (T1=1), so claimed < ceiling means overclaim
            issues.append(
                CoherenceIssue(
                    kind="insufficient_restoration_evidence",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' claims "
                        f"restored_tier={boundary.restored_tier} but evidence "
                        f"supports at most tier {ceiling_tier} "
                        f"({ceiling_taint.value}). §6.3 evidence matrix."
                    ),
                )
            )
    return issues


def check_direct_law_exclusion(
    control_law: str,
    governance_paths: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Check that governance artefacts were not modified during direct law.

    Returns a tuple of warning messages. Empty if control law is not
    "direct" or no governance paths are provided.

    Governance artefacts include: wardline.yaml, overlay files, exception
    register, fingerprint baseline. Under direct law, these MUST NOT be
    modified (§10.5).
    """
    if control_law != "direct":
        return ()
    if not governance_paths:
        return (
            "Control law is 'direct' — governance artefact changes MUST NOT "
            "proceed without enforcement-unavailable governance (§10.5).",
        )
    return tuple(
        f"Control law is 'direct' — modification of governance artefact "
        f"'{path}' is prohibited without enforcement-unavailable governance (§10.5)"
        for path in governance_paths
    )


def check_suppress_overrides(
    overrides: tuple[dict[str, object] | MappingProxyType[str, object], ...],
) -> tuple[str, ...]:
    """Flag rule overrides that set severity to SUPPRESS or OFF.

    These silence findings entirely — a governance risk that should be
    documented and reviewed.
    """
    warnings: list[str] = []
    for ovr in overrides:
        rule_id = ovr.get("id")
        severity = ovr.get("severity")
        if isinstance(severity, str) and severity.upper() in ("SUPPRESS", "OFF"):
            warnings.append(
                f"Rule override '{rule_id}' sets severity to {severity.upper()} — "
                f"findings will be silenced. Review governance justification."
            )
    return tuple(warnings)


def check_boundary_widening(
    boundaries: tuple[BoundaryEntry, ...],
) -> tuple[str, ...]:
    """Flag boundaries where to_tier > from_tier (data flows to less trusted tier).

    This is not always wrong (e.g., writing to external systems), but it's a
    governance signal worth reviewing.
    """
    warnings: list[str] = []
    for b in boundaries:
        if (
            b.from_tier is not None
            and b.to_tier is not None
            and b.to_tier > b.from_tier  # Higher tier number = less trusted
        ):
            warnings.append(
                f"Boundary '{b.function}' declares from_tier={b.from_tier} to "
                f"to_tier={b.to_tier} — data flows to a less trusted tier. "
                f"Review governance justification."
            )
    return tuple(warnings)


def check_exception_volume(
    exceptions: tuple[ExceptionEntry, ...],
    *,
    threshold: int = 50,
    now: datetime.date | None = None,
) -> tuple[str, ...]:
    """Flag when active exception count exceeds threshold.

    A high number of active exceptions may indicate governance fatigue
    or systematic scanner miscalibration.
    """
    if now is None:
        now = datetime.date.today()
    active = [
        e for e in exceptions
        if e.expires is None or datetime.date.fromisoformat(e.expires) >= now
    ]
    if len(active) > threshold:
        return (
            f"Exception register has {len(active)} active exceptions "
            f"(threshold: {threshold}). High volume may indicate governance "
            f"fatigue — review whether scanner calibration or tier assignments "
            f"need adjustment.",
        )
    return ()


def should_gate_on_profile(governance_profile: str) -> bool:
    """Return True if the governance profile requires automatic gating.

    Assurance profile requires automatic enforcement gating — coherence
    failures are hard errors, not warnings. Lite profile allows
    opt-in gating via --gate flag.
    """
    return governance_profile == "assurance"


def check_restoration_evidence_consistency(
    boundaries: tuple[BoundaryEntry, ...],
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
) -> list[CoherenceIssue]:
    """Check that decorator evidence doesn't exceed overlay provenance.

    The overlay is the governance source of truth. If the decorator
    claims higher evidence than the overlay declares, emit a WARNING.
    """
    issues: list[CoherenceIssue] = []
    for boundary in boundaries:
        if boundary.transition != "restoration":
            continue
        if boundary.provenance is None:
            continue

        # Find matching annotation by function name
        matching_ann = None
        for (_fp, qn), anns in annotations.items():
            for ann in anns:
                if ann.canonical_name == "restoration_boundary" and qn == boundary.function:
                    matching_ann = ann
                    break
            if matching_ann is not None:
                break

        if matching_ann is None:
            continue  # No decorator found for this boundary — handled by check_undeclared_boundaries

        # Compare each evidence category: decorator vs overlay
        evidence_keys = [
            ("structural_evidence", "structural"),
            ("semantic_evidence", "semantic"),
            ("integrity_evidence", "integrity"),
            ("institutional_provenance", "institutional"),
        ]
        for dec_key, overlay_key in evidence_keys:
            dec_raw = matching_ann.attrs.get(dec_key)
            overlay_raw = boundary.provenance.get(overlay_key)
            dec_value = bool(dec_raw)
            overlay_value = bool(overlay_raw)

            if dec_value and not overlay_value:
                # Presence divergence: decorator claims evidence overlay doesn't
                issues.append(
                    CoherenceIssue(
                        kind="restoration_evidence_divergence",
                        function=boundary.function,
                        file_path=boundary.overlay_path,
                        detail=(
                            f"Boundary '{boundary.function}' decorator claims "
                            f"{dec_key}={dec_raw!r} but overlay provenance "
                            f"has {overlay_key}={overlay_raw!r}. The overlay "
                            f"is the governance source of truth."
                        ),
                    )
                )
            elif (
                dec_value and overlay_value
                and isinstance(dec_raw, str) and isinstance(overlay_raw, str)
                and dec_raw != overlay_raw
            ):
                # Value divergence: both truthy but different mechanism/attestation
                issues.append(
                    CoherenceIssue(
                        kind="restoration_evidence_divergence",
                        function=boundary.function,
                        file_path=boundary.overlay_path,
                        detail=(
                            f"Boundary '{boundary.function}' decorator has "
                            f"{dec_key}={dec_raw!r} but overlay provenance "
                            f"has {overlay_key}={overlay_raw!r}. Evidence "
                            f"mechanism mismatch."
                        ),
                    )
                )
    return issues
