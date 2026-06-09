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
from wardline.scanner.rules._sink_helpers import (
    TaintedSinkRule,
    enclosing_declared_tier,
    resolved_arg_taints,
    sink_method_calls,
)
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


def _kwargs_may_target_sql_string(call: ast.Call) -> bool:
    """Whether a ``**`` unpack in *call* could supply the SQL-string operation.

    ``True`` when ANY ``**`` unpack is opaque/non-static (a name, comprehension, or dict with
    a ``**``-spread or non-constant key) OR is a literal dict carrying an SQL-string key;
    ``False`` only when EVERY ``**`` unpack is a static literal dict whose keys are all
    non-SQL-string (provably bound-parameter only). Iterates all ``**`` keywords so a clean
    literal followed by an opaque/SQL-keyed one still fails closed. Meaningful only when a
    ``**`` unpack is present — the caller gates on the engine's ``None`` arg-key, which exists
    iff the call has a ``**`` unpack."""
    for kw in call.keywords:
        if kw.arg is not None:
            continue  # a named keyword, keyed by its own name — handled via _SQL_STRING_KEYS
        value = kw.value
        if (
            isinstance(value, ast.Dict)
            and value.keys
            and all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in value.keys)
        ):
            if any(k.value in _SQL_STRING_KEYS for k in value.keys):  # type: ignore[union-attr]
                return True  # literal dict targets an SQL-string key
            # literal dict with only non-SQL keys → bound-parameter only; keep checking others
        else:
            return True  # opaque / non-static ** — cannot isolate; fail closed
    return False


def _sql_string_taint(call: ast.Call, qualname: str, context: AnalysisContext) -> TaintState | None:
    """The least-trusted taint reaching the SQL-STRING argument (the operation), ignoring
    bound-parameter arguments. Fail-closed on positions that cannot be isolated from the
    operation: a ``Starred`` first positional (``execute(*args)``) and a ``**`` unpack that
    could supply the ``operation`` keyword (``execute(**kwargs)`` / ``**{"operation": ...}``).

    The engine collapses a ``**`` unpack to a single ``None``-keyed taint (the worst across the
    unpacked dict's values), so per-key attribution is impossible at this layer: when a literal
    ``**`` dict carries an SQL-string key, the ``None`` taint is treated as reaching the
    operation even if a clean value occupied that key — a deliberate fail-closed
    over-approximation (never an FN). See wardline-8c31463f9f / wardline-e0e44852e7."""
    taints = resolved_arg_taints(call, qualname, context)
    kwargs_is_sql_slot = _kwargs_may_target_sql_string(call)
    worst: TaintState | None = None
    for key, ts in taints.items():
        if ts is None:
            continue
        is_sql_slot = (
            key in _SQL_STRING_KEYS  # operation position 0 / operation-ish keyword
            or key == "*0"  # Starred first positional — cannot isolate; fail closed
            or (key is None and kwargs_is_sql_slot)  # ** unpack that may target the operation
        )
        if is_sql_slot and (worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]):
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
            # Honor a nested def's OWN trust decorator, else inherit the nearest declared
            # enclosing scope's tier — matching the family-wide TaintedSinkRule base
            # (_sink_helpers.enclosing_declared_tier). Without inheritance a tainted execute()
            # in an undecorated nested def evaded the sink (wardline-9b88ec5419); an
            # unconditional strip wrongly overrode a nested def's own tier (wardline-bb8396f96e).
            tier = enclosing_declared_tier(qualname, context.project_taints, context.declared_qualnames)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            for node in sink_method_calls(entity.node, self.SINKS):
                worst = _sql_string_taint(node, qualname, context)
                if worst is None or worst not in RAW_ZONE:
                    continue
                assert isinstance(node.func, ast.Attribute)  # guaranteed by sink_method_calls
                sink_name = node.func.attr
                line = node.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=(
                            f"{qualname}: {worst.value} (untrusted) data reaches the {self.sink_label} "
                            f"sink {sink_name}() at line {line}"
                        ),
                        severity=severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            qualname=qualname,
                            # Call-site-anchored, >1 finding per (rule, path, qualname) possible (execute +
                            # executemany, or a chain ``cur.execute(a).execute(b)``). Discriminate SOURCE-only:
                            # an ENTITY-RELATIVE line offset (call line - def line, invariant to a comment
                            # ABOVE the function: wlfp2/wardline-8654423823) + the call's full lexical SPAN +
                            # the method name. The span (start:end), not the start column alone, separates a
                            # chain's outer/inner calls. Never the resolved arg taint (drifts).
                            taint_path=f"{line - (entity.location.line_start or 0)}:{node.col_offset}:{node.end_col_offset}:{sink_name}",  # noqa: E501
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value, "sink": sink_name, "arg_taint": worst.value},
                    )
                )
        return findings
