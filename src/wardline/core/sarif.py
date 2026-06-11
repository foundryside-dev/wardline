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
from typing import TYPE_CHECKING, Any

from wardline import __version__
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.safe_paths import safe_write_text, write_text_no_follow
from wardline.scanner.flow_trace import build_finding_code_flow

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

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


def _physical_location(location: Location) -> dict[str, Any]:
    phys: dict[str, Any] = {"artifactLocation": {"uri": location.path}}
    region: dict[str, Any] = {}
    if location.line_start is not None:
        region["startLine"] = location.line_start
    if location.line_end is not None:
        region["endLine"] = location.line_end
    if location.col_start is not None:
        region["startColumn"] = location.col_start
    if location.col_end is not None:
        region["endColumn"] = location.col_end
    if region:
        phys["region"] = region
    return phys


def _build_code_flow(finding: Finding, context: AnalysisContext) -> dict[str, Any] | None:
    code_flow = build_finding_code_flow(finding, context)
    if code_flow is None:
        return None

    flow_locations = []
    for step in code_flow.steps:
        flow_locations.append(
            {
                "location": {
                    "physicalLocation": _physical_location(step.location),
                    "message": {"text": step.message},
                },
                "importance": "important",
            },
        )

    return {"threadFlows": [{"locations": flow_locations}]}


def _result(finding: Finding, rule_index: int, context: AnalysisContext | None = None) -> dict[str, Any]:
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
        "partialFingerprints": {"wardlineFingerprint/v2": finding.fingerprint},
        "properties": props,
    }
    if finding.suppressed is not SuppressionState.ACTIVE:
        suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
        if finding.suppression_reason is not None:
            suppression["justification"] = finding.suppression_reason
        result["suppressions"] = [suppression]

    if context is not None and finding.qualname is not None:
        code_flow = _build_code_flow(finding, context)
        if code_flow is not None:
            result["codeFlows"] = [code_flow]

    return result


def build_sarif(findings: Sequence[Finding], context: AnalysisContext | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log with a single run from *findings* (pure).

    ``Kind.METRIC`` findings (engine telemetry such as WLN-L3-LOW-RESOLUTION
    and WLN-ENGINE-METRICS) are excluded from the SARIF output. They carry
    diagnostic statistics about the scan run itself — not actionable code
    issues — and pollute GitHub Code Scanning with noise alerts. The full
    picture (including METRIC findings) is always available in the JSONL sink.
    """
    included = [f for f in findings if f.kind is not Kind.METRIC]
    rule_index: dict[str, int] = {}
    for finding in included:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rule_index)
    rules = [{"id": rid} for rid in rule_index]
    results = [_result(f, rule_index[f.rule_id], context) for f in included]
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
    def __init__(self, path: Path, *, root: Path | None = None) -> None:
        self._path = path
        self._root = root

    def write(self, findings: Sequence[Finding], context: AnalysisContext | None = None) -> None:
        content = json.dumps(build_sarif(findings, context), indent=2, ensure_ascii=False)
        if self._root is not None:
            safe_write_text(self._root, self._path, content, label=self._path.name)
        else:
            write_text_no_follow(self._path, content, label=self._path.name)
