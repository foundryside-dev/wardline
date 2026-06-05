# src/wardline/scanner/rules/sql_injection.py
"""PY-WL-118 — untrusted data reaches SQL/database execution sinks.

Passing untrusted data directly to database queries (``cursor.execute``,
``cursor.executemany``) can lead to SQL Injection (SQLi) (CWE-89).
Tier-modulated; fires only where trust is declared.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Maturity, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.rules._ast_helpers import own_nodes
from wardline.scanner.rules._sink_helpers import TaintedSinkRule, worst_arg_taint
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_SINKS = frozenset({"execute", "executemany"})

METADATA = RuleMetadata(
    rule_id="PY-WL-118",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "Untrusted data reaches a SQL/database execution sink (execute/executemany) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, cursor):\n    cursor.execute(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f(cursor):\n    cursor.execute('SELECT * FROM users')",),
    maturity=Maturity.PREVIEW,
)


class SQLInjection(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "SQL-injection"

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in self.SINKS:
                    worst = worst_arg_taint(node, qualname, context)
                    if worst is not None and worst in RAW_ZONE:
                        line = node.lineno
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                message=(
                                    f"{qualname}: {worst.value} (untrusted) data reaches the {self.sink_label} "
                                    f"sink {node.func.attr}() at line {line}"
                                ),
                                severity=severity,
                                kind=Kind.DEFECT,
                                location=Location(path=entity.location.path, line_start=line),
                                fingerprint=_fp(
                                    rule_id=self.rule_id,
                                    path=entity.location.path,
                                    line_start=line,
                                    qualname=qualname,
                                    taint_path=f"{worst.value}->{node.func.attr}",
                                ),
                                qualname=qualname,
                                properties={"tier": tier.value, "sink": node.func.attr, "arg_taint": worst.value},
                            )
                        )
        return findings
