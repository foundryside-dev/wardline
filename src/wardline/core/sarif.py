# src/wardline/core/sarif.py
"""SARIF 2.1.0 emission (SP4a). Pure findings -> dict; stdlib-only.

A standard interchange format for any SARIF consumer (CI annotations, code-scanning
dashboards). Suppression rides SARIF's native ``result.suppressions`` channel;
the stable fingerprint rides ``partialFingerprints``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from wardline import __version__
from wardline.core.finding import Finding, Severity, SuppressionState

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/foundryside/wardline"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.ERROR: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
    Severity.NONE: "none",
}


def _region(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    location = finding.location
    if location.line_start is not None:
        region["startLine"] = location.line_start
    if location.line_end is not None:
        region["endLine"] = location.line_end
    if location.col_start is not None:
        region["startColumn"] = location.col_start
    if location.col_end is not None:
        region["endColumn"] = location.col_end
    return region


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.path}}
    region = _region(finding)
    if region:
        physical["region"] = region

    props: dict[str, Any] = {
        "kind": finding.kind.value,
        "internalSeverity": finding.severity.value,
    }
    if finding.qualname is not None:
        props["qualname"] = finding.qualname
    if finding.confidence is not None:
        props["confidence"] = finding.confidence
    if finding.related_entities:
        props["relatedEntities"] = list(finding.related_entities)
    if finding.properties:
        props["wardlineProperties"] = dict(finding.properties)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"wardlineFingerprint/v1": finding.fingerprint},
        "properties": props,
    }
    if finding.suppressed is not SuppressionState.ACTIVE:
        suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
        if finding.suppression_reason is not None:
            suppression["justification"] = finding.suppression_reason
        result["suppressions"] = [suppression]
    return result


def build_sarif(findings: Sequence[Finding]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log with a single run from *findings* (pure)."""
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rule_index)
    rules = [{"id": rid} for rid in rule_index]
    results = [_result(f, rule_index[f.rule_id]) for f in findings]
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wardline",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class SarifSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: Sequence[Finding]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(build_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8")
