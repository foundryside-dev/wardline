# src/wardline/scanner/rules/sql_injection.py
"""PY-WL-118 — untrusted data reaches SQL/database execution sinks.

Passing untrusted data directly to database queries (``cursor.execute``,
``cursor.executemany``, ``cursor.executescript``) can lead to SQL Injection
(SQLi) (CWE-89). ``executescript`` (sqlite3 cursor AND connection) runs a
multi-statement script with NO parameter binding at all, so it is strictly more
dangerous than ``execute``. Tier-modulated; fires only where trust is declared.

**Receiver heuristic (FP guard, fail-closed).** ``.execute`` is matched by method
name, so a receiver gate keeps non-database executors (task pools, command
objects) from firing a CWE-89 ERROR. Evidence is consulted strongest-first:

1. *Binding evidence* — the receiver was provably constructed in this function
   (``pool = sqlite3.connect(...)`` / chained ``Cls().execute``): a constructor
   from a known DB driver module fires regardless of the receiver's name; one
   from a known executor module (``concurrent.futures`` etc.) is suppressed.
2. *Name evidence* — exact token match on the receiver's simple name (a ``Name``
   id or the LAST attribute segment, underscore/camelCase split): a DB token
   (``cursor``/``conn``/``db``/``session``/``engine``/...) fires and WINS over a
   non-DB token; a non-DB token (``pool``/``executor``/``worker``/...) alone
   suppresses.
3. *No evidence* — UNKNOWN receivers (opaque names like ``c``/``s``, dynamic
   expressions) FIRE: when unsure we keep the finding, because an FN here is
   worse than an FP. Token matching is exact (never substring), so ``secure``
   can never match ``cur``.

**Text-clause constant exemption (FP guard).** The canonical SQLAlchemy
parameterized pattern ``conn.execute(text("... :id"), {"id": uid})`` wraps a
compile-time CONSTANT in a recognized text-clause constructor — it cannot carry
attacker bytes, so the operation slot is treated as clean. The exemption needs
BOTH the recognized constructor FQN (import-alias aware) and all-constant
arguments: ``text(tainted)`` / ``text(f"...")`` still fire (``text()`` is not a
sanitiser).
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Maturity, Severity
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.rules._sink_helpers import (
    SinkBindings,
    TaintedSinkRule,
    build_sink_finding,
    canonical_call_name,
    collect_sink_bindings,
    dotted_name,
    enclosing_declared_tier,
    module_alias_map,
    resolved_arg_taints,
    sink_method_calls,
)
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

_SINKS = frozenset({"execute", "executemany", "executescript"})

# The DB-API call shape is ``cursor.execute(operation[, parameters])`` /
# ``cursor.executemany(operation, seq_of_params)``: the SQL string is the FIRST
# positional argument (or the ``operation`` keyword), and everything after it is the
# bound-parameter argument. SQLi (CWE-89) is a property of the SQL STRING only —
# untrusted data passed as a *bound parameter* cannot alter the query's structure (it is
# the canonical OWASP mitigation), so taint in the parameters position is NOT SQLi and
# must not fire (wardline-e0e44852e7). This is a deliberate behaviour decision, not just
# a test fix: we gate on the operation-string position and ignore the parameter position.
# ``sql_script`` is sqlite3's parameter name for the executescript slot (its only arg).
_SQL_STRING_KEYS: frozenset[int | str] = frozenset({0, "operation", "sql", "query", "statement", "sql_script"})

# Recognized text-clause constructors (canonical import-resolved FQNs). A call to one
# of these with ALL-constant arguments is a compile-time-fixed SQL string — not
# injectable, regardless of the engine's (unresolvable-third-party) UNKNOWN_RAW verdict.
_TEXT_CLAUSE_FQNS = frozenset(
    {
        "sqlalchemy.text",
        "sqlalchemy.sql.text",
        "sqlalchemy.sql.expression.text",
    }
)

# Receiver-heuristic vocabularies (see the module docstring). Tokens match EXACTLY
# against the underscore/camelCase-split words of the receiver's simple name.
_DB_RECEIVER_TOKENS = frozenset(
    {
        "cursor", "cur", "conn", "connection", "db", "database", "session",
        "engine", "sql", "sqlite", "postgres", "psql", "mysql", "oracle",
        "tx", "txn", "transaction",
    }
)  # fmt: skip
_NON_DB_RECEIVER_TOKENS = frozenset(
    {
        "pool", "executor", "thread", "threads", "scheduler", "worker",
        "workers", "dispatcher", "queue", "task", "tasks", "job", "jobs",
    }
)  # fmt: skip
# Constructor-FQN module prefixes: provably-DB fires regardless of receiver name;
# provably-executor suppresses. Everything else falls through to the name heuristic.
_DB_MODULE_PREFIXES = (
    "sqlite3.", "aiosqlite.", "apsw.", "duckdb.",
    "psycopg2.", "psycopg.", "asyncpg.", "pg8000.",
    "pymysql.", "MySQLdb.", "mysql.", "mariadb.",
    "cx_Oracle.", "oracledb.", "pyodbc.", "sqlalchemy.",
)  # fmt: skip
_NON_DB_MODULE_PREFIXES = ("concurrent.", "multiprocessing.", "threading.", "asyncio.")

_NAME_TOKEN_RE = re.compile(r"[a-z]+")
_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _name_tokens(name: str) -> frozenset[str]:
    """Exact-match word tokens of an identifier: underscore + camelCase split,
    lowercased, digits dropped (``dbConn2`` → {"db", "conn"})."""
    return frozenset(_NAME_TOKEN_RE.findall(_CAMEL_SPLIT_RE.sub("_", name).lower()))


def _is_constant_text_clause(expr: ast.expr, alias_map: Mapping[str, str]) -> bool:
    """Whether *expr* is a recognized text-clause constructor call whose every
    argument is a compile-time constant (the SQL string itself a ``str``).

    Fail-closed everywhere else: a non-recognized wrapper, a non-constant argument
    (Name / f-string / nested call), a ``*``/``**`` splat, or a zero-argument call
    proves nothing and keeps the slot's engine taint."""
    if not isinstance(expr, ast.Call):
        return False
    dotted = dotted_name(expr.func)
    if dotted is None or canonical_call_name(dotted, alias_map) not in _TEXT_CLAUSE_FQNS:
        return False
    if not (expr.args or expr.keywords):
        return False
    for arg in expr.args:
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            return False
    return all(kw.arg is not None and isinstance(kw.value, ast.Constant) for kw in expr.keywords)


def _receiver_is_non_db(call: ast.Call, bindings: SinkBindings, alias_map: Mapping[str, str]) -> bool:
    """Whether the sink call's receiver is CLEARLY a non-database object.

    Returns True ONLY on positive non-DB evidence (binding to an executor-module
    constructor, or a non-DB name token with no DB token); every unknown receiver
    returns False so the rule keeps firing (fail-closed — FN is worse than FP here).
    """
    func = call.func
    assert isinstance(func, ast.Attribute)  # guaranteed by sink_method_calls
    receiver = func.value
    ctor_fqn: str | None = None
    if isinstance(receiver, ast.Name):
        ctor_fqn = bindings.instance_classes.get(receiver.id)
    elif isinstance(receiver, ast.Call):
        dotted = dotted_name(receiver.func)
        ctor_fqn = canonical_call_name(dotted, alias_map) if dotted is not None else None
    if ctor_fqn is not None:
        if ctor_fqn.startswith(_DB_MODULE_PREFIXES):
            return False  # provably a DB-driver object — definite sink
        if ctor_fqn.startswith(_NON_DB_MODULE_PREFIXES):
            return True  # provably an executor/pool-family object
    if isinstance(receiver, ast.Name):
        hint = receiver.id
    elif isinstance(receiver, ast.Attribute):
        hint = receiver.attr  # self.thread_pool → "thread_pool"
    elif ctor_fqn is not None:
        hint = ctor_fqn.rsplit(".", 1)[-1]  # conn.cursor() → "cursor"
    else:
        return False  # dynamic receiver, no evidence — fail closed, fire
    tokens = _name_tokens(hint)
    if tokens & _DB_RECEIVER_TOKENS:
        return False  # DB evidence wins over mixed names ("db_pool")
    return bool(tokens & _NON_DB_RECEIVER_TOKENS)


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


def _sql_string_taint(
    call: ast.Call,
    qualname: str,
    context: AnalysisContext,
    alias_map: Mapping[str, str],
) -> TaintState | None:
    """The least-trusted taint reaching the SQL-STRING argument (the operation), ignoring
    bound-parameter arguments. Fail-closed on positions that cannot be isolated from the
    operation: a ``Starred`` first positional (``execute(*args)``) and a ``**`` unpack that
    could supply the ``operation`` keyword (``execute(**kwargs)`` / ``**{"operation": ...}``).

    An SQL slot whose expression is a recognized text-clause constructor over constants
    (:func:`_is_constant_text_clause`) is skipped — a compile-time-fixed operation string
    is not injectable even when the engine's verdict for the unresolvable third-party
    wrapper is ``UNKNOWN_RAW`` (the canonical SQLAlchemy parameterized-query FP).

    The engine collapses a ``**`` unpack to a single ``None``-keyed taint (the worst across the
    unpacked dict's values), so per-key attribution is impossible at this layer: when a literal
    ``**`` dict carries an SQL-string key, the ``None`` taint is treated as reaching the
    operation even if a clean value occupied that key — a deliberate fail-closed
    over-approximation (never an FN). See wardline-8c31463f9f / wardline-e0e44852e7."""
    taints = resolved_arg_taints(call, qualname, context)
    kwargs_is_sql_slot = _kwargs_may_target_sql_string(call)
    # Slot-key → source expression, so a slot's TAINT can be overridden by what the slot
    # syntactically IS. Starred positionals keep only their "*i" fail-closed key; a ``**``
    # unpack (key None) has no single expression and is never exempted.
    slot_exprs: dict[int | str | None, ast.expr] = {}
    for i, arg in enumerate(call.args):
        if not isinstance(arg, ast.Starred):
            slot_exprs[i] = arg
    for kw in call.keywords:
        if kw.arg is not None:
            slot_exprs[kw.arg] = kw.value
    worst: TaintState | None = None
    for key, ts in taints.items():
        if ts is None:
            continue
        is_sql_slot = (
            key in _SQL_STRING_KEYS  # operation position 0 / operation-ish keyword
            or key == "*0"  # Starred first positional — cannot isolate; fail closed
            or (key is None and kwargs_is_sql_slot)  # ** unpack that may target the operation
        )
        if not is_sql_slot:
            continue
        expr = slot_exprs.get(key)
        if expr is not None and _is_constant_text_clause(expr, alias_map):
            continue  # constant text() clause — compile-time-fixed, not injectable
        if worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]:
            worst = ts
    return worst


METADATA = RuleMetadata(
    rule_id="PY-WL-118",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a SQL/database execution sink (execute/executemany/executescript) "
        "in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, cursor):\n    cursor.execute(read_raw(p))",
        # executescript runs a multi-statement script with NO parameter binding at all —
        # the single most injection-prone DB-API method (wardline-1751b0fac6).
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, cursor):\n    cursor.executescript(read_raw(p))",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(cursor):\n    cursor.execute('SELECT * FROM users')",
        # Parameterized / bound-parameter query: untrusted data in the PARAMETER position
        # (the OWASP-canonical mitigation) is not SQLi and must not fire (wardline-e0e44852e7).
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef g(p, cursor):\n"
        "    cursor.execute('SELECT * FROM t WHERE id = ?', (read_raw(p),))",
        # The canonical SQLAlchemy parameterized query: a compile-time-constant operation
        # string wrapped in text(), with the untrusted value bound — not injectable.
        "from sqlalchemy import text\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef h(p, conn):\n"
        "    conn.execute(text('SELECT * FROM t WHERE id = :id'), {'id': read_raw(p)})",
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
            alias_map = module_alias_map(qualname, context)
            bindings: SinkBindings | None = None  # collected lazily, once per entity
            for node in sink_method_calls(entity.node, self.SINKS):
                if bindings is None:
                    # Function-local bindings only: entities carry no module AST, so a
                    # module-level-constructed receiver falls to the name heuristic
                    # (which fails closed — fires — on anything not clearly non-DB).
                    bindings = collect_sink_bindings(entity.node, alias_map)
                if _receiver_is_non_db(node, bindings, alias_map):
                    continue  # clearly a task-pool/executor object, not a SQL surface
                worst = _sql_string_taint(node, qualname, context, alias_map)
                if worst is None or worst not in RAW_ZONE:
                    continue
                assert isinstance(node.func, ast.Attribute)  # guaranteed by sink_method_calls
                # Shared constructor — identical message shape and wlfp2 discriminator
                # as the base loop, keyed on the METHOD NAME (execute/executemany/
                # executescript), never the resolved receiver (drifts).
                findings.append(
                    build_sink_finding(
                        rule_id=self.rule_id,
                        entity=entity,
                        qualname=qualname,
                        call=node,
                        dotted=node.func.attr,
                        severity=severity,
                        tier=tier,
                        worst=worst,
                        sink_label=self.sink_label,
                    )
                )
        return findings
