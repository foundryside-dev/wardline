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
    properties: Mapping[str, Any] = field(default_factory=dict)

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
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


# --- SP0 PLACEHOLDER ---------------------------------------------------------
# SP1 REPLACES this to fold in taint-path identity so two paths into one sink
# (same file/rule/line, different path) get distinct fingerprints. Do not treat
# this as the final scheme.
def compute_placeholder_fingerprint(
    rule_id: str, path: str, line_start: int | None, message: str
) -> str:
    digest = hashlib.sha256()
    digest.update(f"{rule_id}\x00{path}\x00{line_start}\x00{message}".encode())
    return digest.hexdigest()
