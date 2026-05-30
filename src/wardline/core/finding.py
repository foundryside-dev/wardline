# src/wardline/core/finding.py
"""The Finding record — the central cross-subproject contract (stdlib-only).

Designed as a superset of Filigree's scan-results intake so SP4 emission is
serialization, not translation. Wardline owns the analysis *fact*; finding
*lifecycle* (status, seen_count, issue_id, timestamps) is Filigree's domain
and is deliberately absent here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"
    NONE = "NONE"  # facts / metrics carry no defect severity


class Kind(StrEnum):
    DEFECT = "defect"
    FACT = "fact"
    CLASSIFICATION = "classification"
    METRIC = "metric"
    SUGGESTION = "suggestion"


class SuppressionState(StrEnum):
    ACTIVE = "active"        # not suppressed — the default
    BASELINED = "baselined"  # matched a baseline fingerprint
    WAIVED = "waived"        # matched an active waiver


@dataclass(frozen=True, slots=True)
class Location:
    path: str  # repo-relative POSIX path; Filigree's file_path anchor
    line_start: int | None = None
    line_end: int | None = None
    col_start: int | None = None  # retained for SARIF; Filigree ignores columns
    col_end: int | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str  # namespaced WLN-*
    message: str
    severity: Severity
    kind: Kind
    location: Location
    fingerprint: str  # stable cross-run identity (SP1 folds in taint-path identity)
    suggestion: str | None = None
    qualname: str | None = None  # dotted module.qualified_name (Clarion reconciliation key)
    confidence: float | None = None
    related_entities: tuple[str, ...] = ()
    # Immutability is shallow: the contained mapping is not deep-frozen and must
    # be treated as read-only by convention. SP1 may enforce via MappingProxyType.
    properties: Mapping[str, Any] = field(default_factory=dict)
    suppressed: SuppressionState = SuppressionState.ACTIVE
    suppression_reason: str | None = None

    def to_jsonl(self) -> str:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "kind": self.kind.value,
            "location": {
                "path": self.location.path,
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
                "col_start": self.location.col_start,
                "col_end": self.location.col_end,
            },
            "fingerprint": self.fingerprint,
            "suggestion": self.suggestion,
            "qualname": self.qualname,
            "confidence": self.confidence,
            "related_entities": list(self.related_entities),
            "properties": dict(self.properties),
            "suppressed": self.suppressed.value,
            "suppression_reason": self.suppression_reason,
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


# --- Finding fingerprint (SP2 §7) --------------------------------------------
# Stable cross-run identity that folds in qualname + a taint-path signature so
# two taint paths into one sink (same file/rule/line, different path) get
# DISTINCT fingerprints (Filigree drift constraint). Discrimination is only as
# fine as the supplied ``taint_path`` — callers derive it from ``taint_provenance``
# (a single best-callee, not a full path), so two paths sharing best-callee AND
# returned taint will still collide. That is the spec's accepted granularity.
def compute_finding_fingerprint(
    *,
    rule_id: str,
    path: str,
    line_start: int | None,
    qualname: str | None = None,
    taint_path: str | None = None,
) -> str:
    digest = hashlib.sha256()
    parts = (rule_id, path, str(line_start), qualname or "", taint_path or "")
    digest.update("\x00".join(parts).encode())
    return digest.hexdigest()


# --- Loom wire mapping (pure; SP4 uses these to build the scan-results body) -
_SEVERITY_TO_FILIGREE: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.ERROR: "high",
    Severity.WARN: "medium",
    Severity.INFO: "low",
    Severity.NONE: "info",
}


def severity_to_filigree(severity: Severity) -> str:
    """Map Wardline's 4-level (+NONE) vocabulary to Filigree's 5-level set."""
    return _SEVERITY_TO_FILIGREE[severity]


def to_filigree_metadata(finding: Finding) -> dict[str, Any]:
    """Build the ``metadata.wardline.*`` subtree (semantic JSON, not byte-stable)."""
    wardline: dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "internal_severity": finding.severity.value,
        "kind": finding.kind.value,
    }
    if finding.qualname is not None:
        wardline["qualname"] = finding.qualname
    if finding.confidence is not None:
        wardline["confidence"] = finding.confidence
    if finding.related_entities:
        wardline["related_entities"] = list(finding.related_entities)
    if finding.properties:
        wardline["properties"] = dict(finding.properties)
    if finding.suppressed is not SuppressionState.ACTIVE:
        wardline["suppressed"] = finding.suppressed.value
        if finding.suppression_reason is not None:
            wardline["suppression_reason"] = finding.suppression_reason
    return {"wardline": wardline}
