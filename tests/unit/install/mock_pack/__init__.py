# tests/unit/install/mock_pack/__init__.py
"""A mock trust-grammar pack for testing."""

from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, TrustGrammar
from wardline.scanner.taint.provider import FunctionTaint


class MockRule:
    rule_id = "PY-WL-901"

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.severity = base_severity or Severity.WARN

    def check(self, context) -> list[Finding]:
        findings = []
        for _qualname, entity in context.entities.items():
            if entity.node.name == "violator":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message="Found a violator!",
                        severity=self.severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=entity.location.line_start),
                        fingerprint=f"{self.rule_id}:{entity.location.path}:{entity.location.line_start}",
                    )
                )
        return findings


def _seed_mock_boundary(levels) -> FunctionTaint:
    return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.GUARDED)


mock_boundary = BoundaryType(
    canonical_name="mock_boundary",
    module_prefix="tests.unit.install.mock_pack",
    group=1,
    level_args=(),
    seed=_seed_mock_boundary,
    builtin=False,
)

grammar = TrustGrammar(
    boundary_types=(mock_boundary,),
    rules=(MockRule,),
)

config = {
    "exclude": ["**/mock_exclude/**"],
    "rules": {
        "severity": {
            "PY-WL-103": "INFO",
        }
    },
}
