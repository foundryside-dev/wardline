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
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.rules._ast_helpers import own_nodes
from wardline.scanner.rules._sink_helpers import TaintedSinkRule, resolved_arg_taints
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_SINKS = frozenset({"execute", "executemany"})

# The DB-API call shape is ``cursor.execute(operation[, parameters])`` /
# ``cursor.executemany(operation, seq_of_params)``: the SQL string is the FIRST
# positional argument (or the ``operation`` keyword), and everything after it is the
# bound-parameter argument. SQLi (CWE-89) is a property of the SQL STRING only —
# untrusted data passed as a *bound parameter* cannot alter the query's structure (it is
# the canonical OWASP mitigation), so taint in the parameters position is NOT SQLi and
# must not fire (wardline-e0e44852e7). This is a deliberate behaviour decision, not just
# a test fix: we gate on the operation-string position and ignore the parameter position.
_SQL_STRING_KEYS: frozenset[int | str] = frozenset({0, "operation", "sql", "query", "statement"})


def _sql_string_taint(call: ast.Call, qualname: str, context: AnalysisContext) -> TaintState | None:
    """The least-trusted taint reaching the SQL-STRING argument (the operation), ignoring
    bound-parameter arguments. Fail-closed: a ``Starred`` first positional
    (``execute(*args)``) cannot be split into operation-vs-params, so its taint is taken
    as the operation's (treated as potentially-SQL)."""
    taints = resolved_arg_taints(call, qualname, context)
    if "*0" in taints:  # splatted operation — cannot isolate the SQL string; fail closed
        return taints.get(0)
    worst: TaintState | None = None
    for key, ts in taints.items():
        if key in _SQL_STRING_KEYS and ts is not None and (worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]):
            worst = ts
    return worst


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
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(cursor):\n    cursor.execute('SELECT * FROM users')",
        # Parameterized / bound-parameter query: untrusted data in the PARAMETER position
        # (the OWASP-canonical mitigation) is not SQLi and must not fire (wardline-e0e44852e7).
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef g(p, cursor):\n"
        "    cursor.execute('SELECT * FROM t WHERE id = ?', (read_raw(p),))",
    ),
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
            # Strip ``.<locals>.`` so a nested def inherits its enclosing trusted tier,
            # matching the family-wide TaintedSinkRule base (_sink_helpers.py) — without
            # this, a tainted execute() wrapped in a nested function evaded the
            # highest-severity sink (wardline-9b88ec5419).
            lookup_name = qualname.split(".<locals>.")[0]
            tier = context.project_taints.get(lookup_name, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in self.SINKS:
                    worst = _sql_string_taint(node, qualname, context)
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
