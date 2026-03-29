"""SARIF v2.1.0 output for wardline scan results.

Converts Finding dataclasses into SARIF-compliant JSON for
integration with code-analysis dashboards and CI pipelines.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core.severity import RuleId, Severity

if TYPE_CHECKING:
    from wardline.scanner.context import Finding

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.SUPPRESS: "note",
}

# Short descriptions for each canonical rule ID.
_RULE_SHORT_DESCRIPTIONS: dict[RuleId, str] = {
    RuleId.PY_WL_001: "Dict key access with fallback default",
    RuleId.PY_WL_002: "Attribute access with fallback default",
    RuleId.PY_WL_003: "Existence-checking as structural gate",
    RuleId.PY_WL_004: "Broad exception handler",
    RuleId.PY_WL_005: "Silent exception handler",
    RuleId.PY_WL_006: "Audit-critical write in broad exception handler",
    RuleId.PY_WL_007: "Runtime type-checking on internal data",
    RuleId.PY_WL_008: "Validation boundary with no rejection path",
    RuleId.PY_WL_009: "Semantic validation without prior shape validation",
    RuleId.SCN_021: "Contradictory or suspicious wardline decorator combination",
    RuleId.SUP_001: "Supplementary decorator contract violation",
    RuleId.SCN_022: "Field-completeness verification for @all_fields_mapped",
    RuleId.PY_WL_001_GOVERNED_DEFAULT: "Governed default value (diagnostic)",
    RuleId.PY_WL_001_UNGOVERNED_DEFAULT: "Ungoverned schema_default() — no overlay boundary (diagnostic)",
    RuleId.WARDLINE_UNRESOLVED_DECORATOR: "Unresolved decorator (diagnostic)",
    RuleId.WARDLINE_DYNAMIC_IMPORT: "Dynamic import of wardline module (diagnostic)",
    RuleId.TOOL_ERROR: "Internal tool error",
    RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED: (
        "Registry mismatch allowed (diagnostic)"
    ),
    RuleId.GOVERNANCE_RULE_DISABLED: "Rule disabled by configuration (governance)",
    RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION: (
        "Permissive distribution allowed (governance)"
    ),
    RuleId.GOVERNANCE_STALE_EXCEPTION: "Stale exception — AST fingerprint mismatch (governance)",
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE: "Unknown agent provenance on exception (governance)",
    RuleId.GOVERNANCE_RECURRING_EXCEPTION: "Recurring exception — multiple renewals (governance)",
    RuleId.GOVERNANCE_BATCH_REFRESH: "Batch exception refresh performed (governance)",
    RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION: "Exception has no expiry date (governance)",
    RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT: "Exception taint state no longer matches function's effective taint",
    RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE: "Exception granted at lower analysis level than active scan",
    RuleId.GOVERNANCE_EXCEPTION_SEVERITY_DRIFT: "Exception severity_at_grant differs from current finding severity",
    RuleId.GOVERNANCE_TAINT_DEGRADED: "Taint assignment degraded — file scanned with empty fallback taint map",
    RuleId.GOVERNANCE_TAINT_CONFLICT: "Conflicting taint decorators on function — first decorator wins, others ignored",
    RuleId.GOVERNANCE_RESTORATION_OVERCLAIM: "Restoration decorator claims tier unsupported by declared evidence (governance)",
    RuleId.GOVERNANCE_MODULE_TIERS_BLANKET: "Module-level taint default covers >80% of functions with no decorator evidence",
    RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED: "High-trust module_tiers entry with zero wardline decorator usage in file",
    RuleId.GOVERNANCE_CUSTOM_KNOWN_VALIDATOR: "Custom known_validators entry (governance)",
    RuleId.GOVERNANCE_FILE_SKIPPED: "File skipped due to parse failure (governance)",
    RuleId.L3_LOW_RESOLUTION: "L3 call-graph taint based on minority of call edges (>70% unresolved)",
    RuleId.L3_CONVERGENCE_BOUND: "L3 propagation hit iteration safety bound — results may be incomplete",
}

# Pseudo-rule-IDs that should NOT appear in implementedRules.
_PSEUDO_RULE_IDS: frozenset[RuleId] = frozenset(
    {
        RuleId.PY_WL_001_GOVERNED_DEFAULT,
        RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
        RuleId.WARDLINE_UNRESOLVED_DECORATOR,
        RuleId.WARDLINE_DYNAMIC_IMPORT,
        RuleId.TOOL_ERROR,
        RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED,
        RuleId.GOVERNANCE_RULE_DISABLED,
        RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION,
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
        RuleId.GOVERNANCE_RECURRING_EXCEPTION,
        RuleId.GOVERNANCE_BATCH_REFRESH,
        RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
        RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT,
        RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE,
        RuleId.GOVERNANCE_EXCEPTION_SEVERITY_DRIFT,
        RuleId.GOVERNANCE_TAINT_DEGRADED,
        RuleId.GOVERNANCE_TAINT_CONFLICT,
        RuleId.GOVERNANCE_RESTORATION_OVERCLAIM,
        RuleId.GOVERNANCE_MODULE_TIERS_BLANKET,
        RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED,
        RuleId.GOVERNANCE_CUSTOM_KNOWN_VALIDATOR,
        RuleId.GOVERNANCE_FILE_SKIPPED,
        RuleId.L3_LOW_RESOLUTION,
        RuleId.L3_CONVERGENCE_BOUND,
        RuleId.TEST_STUB,
    }
)


@dataclass(frozen=True)
class GovernanceEvent:
    """A discrete governance event for audit trail (§9)."""

    event_type: str
    message: str
    timestamp: str | None = None  # ISO 8601, None in verification mode


def compute_control_law(
    *,
    manifest_unavailable: bool = False,
    ratification_overdue: bool = False,
    conformance_gaps: tuple[str, ...] = (),
    rules_disabled: tuple[str, ...] = (),
    stale_exception_count: int = 0,
) -> tuple[str, tuple[str, ...]]:
    """Compute the enforcement control law state per spec §9.5.

    Returns (law, degradations) where law is "normal", "alternate", or
    "direct" and degradations is a sorted tuple of degradation condition
    names.

    Direct law means no meaningful enforcement output: manifest unavailable
    or trust topology cannot be established. Alternate law means degraded
    but running. Normal law means full enforcement capability.
    """
    if manifest_unavailable:
        return "direct", ("manifest_unavailable",)

    degradations: list[str] = []
    if ratification_overdue:
        degradations.append("ratification_overdue")
    if conformance_gaps:
        degradations.append("conformance_gaps_present")
    if rules_disabled:
        degradations.append("rules_disabled")
    if stale_exception_count > 0:
        degradations.append("stale_exceptions_present")

    degradations.sort()
    law = "alternate" if degradations else "normal"
    return law, tuple(degradations)


def _severity_rank(severity: Severity) -> int:
    """Return a numeric rank for severity (higher = worse)."""
    return {Severity.SUPPRESS: 0, Severity.WARNING: 1, Severity.ERROR: 2}.get(
        severity, -1
    )


def _clean_none(d: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *d* with all ``None``-valued keys removed."""
    return {k: v for k, v in d.items() if v is not None}


def _make_region(finding: Finding) -> dict[str, Any]:
    """Build a SARIF region dict, omitting None fields."""
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,  # SARIF uses 1-based columns
    }
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    if finding.end_col is not None:
        region["endColumn"] = finding.end_col + 1
    return region


def _normalize_artifact_uri(file_path: str, base_path: str | None) -> str:
    """Return a SARIF-friendly artifact URI for *file_path*.

    SARIF consumers expect project-relative URIs when possible. If
    ``base_path`` is provided and the finding path is under that root,
    emit a relative POSIX path. Otherwise preserve the original path,
    normalized to POSIX separators.
    """
    path = Path(file_path)
    if base_path is not None:
        base = Path(base_path)
        with contextlib.suppress(ValueError):
            path = path.resolve().relative_to(base.resolve())
    return path.as_posix()


def _make_result(finding: Finding, *, base_path: str | None) -> dict[str, Any]:
    """Convert a single Finding to a SARIF result entry."""
    # Mandatory properties (§A.3) — always present, never filtered by _clean_none.
    properties: dict[str, Any] = {
        "wardline.rule": str(finding.rule_id),
        "wardline.taintState": (
            str(finding.taint_state)
            if finding.taint_state is not None
            else "UNKNOWN"
        ),
        "wardline.severity": str(finding.severity),
        "wardline.exceptionability": str(finding.exceptionability),
        "wardline.analysisLevel": finding.analysis_level,
    }
    # Optional properties — omit when None.
    properties.update(_clean_none({
        "wardline.qualname": finding.qualname,
        "wardline.sourceSnippet": finding.source_snippet,
    }))
    if finding.exception_id is not None:
        properties["wardline.exceptionId"] = finding.exception_id
    if finding.exception_expires is not None:
        properties["wardline.exceptionExpires"] = finding.exception_expires
    if finding.retroactive_scan:
        properties["wardline.retroactiveScan"] = True
    return {
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note"),
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _normalize_artifact_uri(
                            finding.file_path, base_path
                        )
                    },
                    "region": _make_region(finding),
                },
            }
        ],
        "message": {"text": finding.message},
        "properties": properties,
        "ruleId": str(finding.rule_id),
    }


def _make_rule_descriptor(rule_id: RuleId, severity: Severity) -> dict[str, Any]:
    """Build a SARIF rule descriptor for a given rule ID."""
    return {
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
        },
        "id": str(rule_id),
        "shortDescription": {
            "text": _RULE_SHORT_DESCRIPTIONS.get(
                rule_id, f"Wardline rule {rule_id}"
            ),
        },
    }


@dataclass
class SarifReport:
    """Holds scan results and produces SARIF v2.1.0 output."""

    findings: list[Finding] = field(default_factory=list)
    tool_version: str = "1.0.0"
    verification_mode: bool = False
    implemented_rule_ids: frozenset[RuleId] | None = None
    base_path: str | None = None
    unknown_raw_count: int = 0
    unresolved_decorator_count: int = 0
    files_with_degraded_taint: int = 0
    active_exception_count: int = 0
    stale_exception_count: int = 0
    expedited_exception_ratio: float = 0.0
    governance_profile: str = "lite"
    # WP 2.4: Governance metadata
    control_law: str = "normal"
    control_law_degradations: tuple[str, ...] = ()
    analysis_level: int = 1
    manifest_hash: str | None = None
    scan_timestamp: str | None = None
    commit_ref: str | None = None
    # Gap 3: Run-level identity properties (§10.1)
    input_hash: str = ""
    input_files: int = 0
    overlay_hashes: tuple[str, ...] = ()
    coverage_ratio: float | None = None
    conformance_gaps: tuple[str, ...] = ()
    retroactive_scan: bool = False
    retroactive_scan_range: str | None = None
    # GOV-005: Structured governance audit events (§9)
    governance_events: tuple[GovernanceEvent, ...] = ()

    def _implemented_rules(self) -> list[str]:
        """Return sorted list of canonical rule ID values (excludes pseudo-IDs).

        If ``implemented_rule_ids`` is set, uses that (from loaded rules).
        Otherwise falls back to all canonical RuleId members.
        """
        if self.implemented_rule_ids is not None:
            return sorted(
                r.value for r in self.implemented_rule_ids
                if r not in _PSEUDO_RULE_IDS
            )
        return sorted(
            r.value for r in RuleId if r not in _PSEUDO_RULE_IDS
        )

    def _collect_rule_descriptors(self) -> list[dict[str, Any]]:
        """Build deduplicated, sorted rule descriptors from findings."""
        # Map rule_id -> worst severity seen for that rule.
        rule_severity: dict[RuleId, Severity] = {}
        for f in self.findings:
            existing = rule_severity.get(f.rule_id)
            if existing is None or _severity_rank(f.severity) > _severity_rank(existing):
                rule_severity[f.rule_id] = f.severity
        # Sort by rule ID string for determinism.
        return [
            _make_rule_descriptor(rid, sev)
            for rid, sev in sorted(rule_severity.items(), key=lambda x: str(x[0]))
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a SARIF v2.1.0 compliant dict."""
        # Sort findings for deterministic output.
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (f.file_path, f.line, f.col, str(f.rule_id)),
        )

        results = [
            _make_result(f, base_path=self.base_path)
            for f in sorted_findings
        ]
        rules = self._collect_rule_descriptors()

        run: dict[str, Any] = {
            "properties": {
                "wardline.analysisLevel": self.analysis_level,
                **({"wardline.commitRef": self.commit_ref}
                   if not self.verification_mode and self.commit_ref
                   else {}),
                "wardline.conformanceGaps": list(self.conformance_gaps),
                "wardline.controlLaw": self.control_law,
                **({"wardline.controlLawDegradations": list(self.control_law_degradations)}
                   if self.control_law_degradations else {}),
                **({"wardline.coverageRatio": round(self.coverage_ratio, 4)}
                   if self.coverage_ratio is not None else {}),
                **({"wardline.retroactiveScan": True,
                    "wardline.retroactiveScanRange": self.retroactive_scan_range}
                   if self.retroactive_scan and self.retroactive_scan_range
                   else {}),
                "wardline.governanceProfile": self.governance_profile,
                "wardline.implementedRules": self._implemented_rules(),
                "wardline.inputFiles": self.input_files,
                "wardline.inputHash": self.input_hash,
                **({"wardline.manifestHash": self.manifest_hash}
                   if self.manifest_hash is not None
                   else {}),
                "wardline.overlayHashes": list(self.overlay_hashes),
                "wardline.propertyBagVersion": "0.4",
                **({"wardline.scanTimestamp": self.scan_timestamp}
                   if not self.verification_mode and self.scan_timestamp
                   else {}),
                "wardline.errorFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.ERROR
                ),
                "wardline.exceptedFindingCount": sum(
                    1 for f in self.findings if f.exception_id is not None
                ),
                "wardline.gateBlockingCount": sum(
                    1
                    for f in self.findings
                    if f.severity == Severity.ERROR and f.exception_id is None
                ),
                "wardline.suppressedCellFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.SUPPRESS
                ),
                "wardline.warningFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.WARNING
                ),
                "wardline.unknownRawFunctionCount": self.unknown_raw_count,
                "wardline.unresolvedDecoratorCount": self.unresolved_decorator_count,
                "wardline.filesWithDegradedTaint": self.files_with_degraded_taint,
                "wardline.activeExceptionCount": self.active_exception_count,
                "wardline.staleExceptionCount": self.stale_exception_count,
                "wardline.expeditedExceptionRatio": round(self.expedited_exception_ratio, 3),
                **({"wardline.governanceEvents": [
                    {"eventType": e.event_type, "message": e.message,
                     **({"timestamp": e.timestamp} if e.timestamp else {})}
                    for e in self.governance_events
                ]} if self.governance_events else {}),
            },
            "results": results,
            "tool": {
                "driver": {
                    "informationUri": "https://wardline.dev",
                    "name": "wardline",
                    "rules": rules,
                    "version": self.tool_version,
                },
            },
        }

        return {
            "$schema": _SARIF_SCHEMA,
            "runs": [run],
            "version": "2.1.0",
        }

    def to_json_string(self) -> str:
        """Return the SARIF report as a JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_json(self, path: str | Path) -> None:
        """Write the SARIF report to a JSON file."""
        Path(path).write_text(self.to_json_string(), encoding="utf-8")
