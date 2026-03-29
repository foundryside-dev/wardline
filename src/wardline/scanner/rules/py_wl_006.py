"""PY-WL-006: Audit-critical writes in broad exception handlers.

Detects code that performs audit-critical writes inside broad exception
handlers (``except Exception``, ``except BaseException``, bare
``except:``).

The concern: if the audit write itself raises, the broad handler masks
the failure — the audit trail silently loses a record and the program
continues as if everything were fine.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from wardline.core.severity import RuleId
from wardline.scanner.rules.base import (
    RuleBase,
    call_name,
    decorator_name,
    iter_exception_handlers,
    receiver_name,
    walk_skip_nested_defs,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

_BROAD_NAMES = frozenset({"Exception", "BaseException"})
_INTEGRITY_DECORATORS = frozenset({"integral_writer", "integrity_critical"})
_AUDIT_ATTR_PREFIXES = ("audit", "record", "emit")
_AUDIT_FUNC_NAMES = frozenset({"audit", "record", "emit"})

@dataclass(frozen=True)
class _BlockAnalysis:
    """Local control-flow summary for audit-path analysis."""

    continue_states: frozenset[bool] = frozenset()
    bypass_nodes: tuple[ast.AST, ...] = field(default_factory=tuple)


def _iter_defs_with_qualnames(
    nodes: list[ast.stmt],
    prefix: str = "",
) -> Iterator[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Yield dotted qualnames for all nested functions in lexical order."""
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{prefix}.{node.name}" if prefix else node.name
            yield qualname, node
            yield from _iter_defs_with_qualnames(node.body, qualname)
        elif isinstance(node, ast.ClassDef):
            class_prefix = f"{prefix}.{node.name}" if prefix else node.name
            yield from _iter_defs_with_qualnames(node.body, class_prefix)


def _is_broad_handler(handler: ast.ExceptHandler) -> bool:
    """Check if handler catches broadly (Exception, BaseException, bare)."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in _BROAD_NAMES:
        return True
    if isinstance(handler.type, ast.Attribute) and handler.type.attr in _BROAD_NAMES:
        return True
    if isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id in _BROAD_NAMES:
                return True
            if isinstance(elt, ast.Attribute) and elt.attr in _BROAD_NAMES:
                return True
    return False


def _looks_audit_scoped(call: ast.Call) -> bool:
    """Heuristic for obviously audit-shaped sinks, excluding telemetry."""
    if isinstance(call.func, ast.Name):
        return call.func.id in _AUDIT_FUNC_NAMES
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        receiver = receiver_name(call.func.value) or ""
        if any(attr == prefix or attr.startswith(prefix + "_") for prefix in _AUDIT_ATTR_PREFIXES):
            return True
        receiver_lower = receiver.lower()
        return "audit" in receiver_lower or "ledger" in receiver_lower
    return False


def _is_audit_call(call: ast.Call, local_audit_names: frozenset[str]) -> bool:
    """Check if a Call node looks like an audit-critical write."""
    name = call_name(call)
    if name is not None and name in local_audit_names:
        return True
    return _looks_audit_scoped(call)


def _contains_audit_call(
    node: ast.AST,
    local_audit_names: frozenset[str],
) -> bool:
    """Return True when *node* contains an audit-shaped call."""
    return any(
        isinstance(child, ast.Call) and _is_audit_call(child, local_audit_names)
        for child in walk_skip_nested_defs(node)
    )


def _has_normal_path_audit(
    stmts: list[ast.stmt],
    local_audit_names: frozenset[str],
) -> bool:
    """Return True when audit appears on a non-handler path.

    This keeps the dominance pass focused on "success can bypass audit"
    scenarios instead of double-reporting functions that only audit in
    exception handlers.
    """
    for stmt in stmts:
        match stmt:
            case ast.Try():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.finalbody, local_audit_names):
                    return True
            case ast.If():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
            case ast.Match():
                if any(
                    _has_normal_path_audit(case.body, local_audit_names)
                    for case in stmt.cases
                ):
                    return True
            case ast.For() | ast.AsyncFor() | ast.While():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
            case _ if _contains_audit_call(stmt, local_audit_names):
                return True
    return False


class RulePyWl006(RuleBase):
    """Detect audit-critical writes inside broad exception handlers.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_006

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path
        self._local_audit_names: frozenset[str] = frozenset()

    def visit_Module(self, node: ast.Module) -> None:
        """Pre-scan the module for locally declared audit call targets."""
        local_names: set[str] = set()
        for qualname, func in _iter_defs_with_qualnames(node.body):
            if any(
                decorator_name(decorator) in _INTEGRITY_DECORATORS
                for decorator in func.decorator_list
            ):
                local_names.add(qualname.split(".")[-1])
        self._local_audit_names = frozenset(local_names)
        self.generic_visit(node)

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Check broad-handler masking and local success-path audit bypasses."""
        # ── Check broad handlers for masked audit calls ──
        for handler in iter_exception_handlers(node):
            self._check_broad_handler_for_audit(handler)

        # ── Dominance analysis ──
        if not _has_normal_path_audit(node.body, self._local_audit_names):
            return

        analysis = self._analyze_block(node.body, audited=False)
        bypass_nodes = list(analysis.bypass_nodes)
        if False in analysis.continue_states:
            bypass_nodes.append(node)

        seen: set[tuple[int, int, int | None, int | None]] = set()
        for bypass_node in bypass_nodes:
            key = (
                getattr(bypass_node, "lineno", 0),
                getattr(bypass_node, "col_offset", 0),
                getattr(bypass_node, "end_lineno", None),
                getattr(bypass_node, "end_col_offset", None),
            )
            if key in seen:
                continue
            seen.add(key)
            self._emit_matrix_finding(
                bypass_node,
                (
                    "Audit-critical path has a success/fallback branch "
                    "that can bypass audit"
                ),
            )

    def _check_broad_handler_for_audit(self, handler: ast.ExceptHandler) -> None:
        """Check a single broad handler for audit-critical calls."""
        if not _is_broad_handler(handler):
            return
        for handler_node in ast.walk(handler):
            if (
                isinstance(handler_node, ast.Call)
                and _is_audit_call(handler_node, self._local_audit_names)
            ):
                self._emit_matrix_finding(
                    handler_node,
                    (
                        "Audit-critical write in broad exception handler — "
                        "if the write fails, the broad handler masks the failure"
                    ),
                )

    def _analyze_block(
        self,
        stmts: list[ast.stmt],
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze a statement block for success paths that bypass audit."""
        continue_states: set[bool] = {audited}
        bypass_nodes: list[ast.AST] = []
        for stmt in stmts:
            next_states: set[bool] = set()
            for state in continue_states:
                stmt_analysis = self._analyze_stmt(stmt, audited=state)
                next_states.update(stmt_analysis.continue_states)
                bypass_nodes.extend(stmt_analysis.bypass_nodes)
            continue_states = next_states
            if not continue_states:
                break
        return _BlockAnalysis(
            continue_states=frozenset(continue_states),
            bypass_nodes=tuple(bypass_nodes),
        )

    def _analyze_stmt(
        self,
        stmt: ast.stmt,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze one statement under the given incoming audit state."""
        match stmt:
            case ast.Return():
                return self._analyze_return(stmt, audited=audited)
            case ast.Raise():
                return _BlockAnalysis()
            case ast.If():
                return self._analyze_if(stmt, audited=audited)
            case ast.Try():
                return self._analyze_try(stmt, audited=audited)
            case ast.For() | ast.AsyncFor() | ast.While():
                return self._analyze_loop(stmt, audited=audited)
            case ast.Match():
                return self._analyze_match(stmt, audited=audited)
            case _:
                next_audited = audited or _contains_audit_call(
                    stmt,
                    self._local_audit_names,
                )
                return _BlockAnalysis(continue_states=frozenset({next_audited}))

    def _analyze_return(
        self,
        stmt: ast.Return,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze a return as a success exit."""
        audited_here = audited or (
            stmt.value is not None
            and _contains_audit_call(stmt.value, self._local_audit_names)
        )
        if audited_here:
            return _BlockAnalysis()
        return _BlockAnalysis(bypass_nodes=(stmt,))

    def _analyze_if(
        self,
        stmt: ast.If,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze both branches of an if statement."""
        body = self._analyze_block(stmt.body, audited=audited)
        orelse = (
            self._analyze_block(stmt.orelse, audited=audited)
            if stmt.orelse
            else _BlockAnalysis(continue_states=frozenset({audited}))
        )
        return _BlockAnalysis(
            continue_states=body.continue_states | orelse.continue_states,
            bypass_nodes=body.bypass_nodes + orelse.bypass_nodes,
        )

    def _analyze_try(
        self,
        stmt: ast.Try,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze try/except/else/finally for local success bypasses."""
        body = self._analyze_block(stmt.body, audited=audited)
        normal_states = set(body.continue_states)

        if stmt.orelse:
            else_states: set[bool] = set()
            else_bypass_nodes: list[ast.AST] = list(body.bypass_nodes)
            for state in normal_states:
                else_analysis = self._analyze_block(stmt.orelse, audited=state)
                else_states.update(else_analysis.continue_states)
                else_bypass_nodes.extend(else_analysis.bypass_nodes)
            normal_states = else_states
            bypass_nodes: list[ast.AST] = else_bypass_nodes
        else:
            bypass_nodes = list(body.bypass_nodes)

        handler_states: set[bool] = set()
        for handler in stmt.handlers:
            handler_analysis = self._analyze_block(handler.body, audited=audited)
            handler_states.update(handler_analysis.continue_states)
            bypass_nodes.extend(handler_analysis.bypass_nodes)

        combined_states = normal_states | handler_states
        if stmt.finalbody:
            final_states: set[bool] = set()
            for state in combined_states:
                final_analysis = self._analyze_block(
                    stmt.finalbody,
                    audited=state,
                )
                final_states.update(final_analysis.continue_states)
                bypass_nodes.extend(final_analysis.bypass_nodes)
            combined_states = final_states

        return _BlockAnalysis(
            continue_states=frozenset(combined_states),
            bypass_nodes=tuple(bypass_nodes),
        )

    def _analyze_loop(
        self,
        stmt: ast.For | ast.AsyncFor | ast.While,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Conservative first-pass handling for loops.

        Loops may execute zero times, so the incoming state always remains
        possible. A single body pass gives us useful local branch coverage
        without needing loop fixed points in v1.
        """
        body = self._analyze_block(stmt.body, audited=audited)
        orelse = self._analyze_block(stmt.orelse, audited=audited)
        return _BlockAnalysis(
            continue_states=(
                frozenset({audited})
                | body.continue_states
                | orelse.continue_states
            ),
            bypass_nodes=body.bypass_nodes + orelse.bypass_nodes,
        )

    def _analyze_match(
        self,
        stmt: ast.Match,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze match/case as a multi-branch conditional."""
        continue_states: set[bool] = set()
        bypass_nodes: list[ast.AST] = []
        for case in stmt.cases:
            case_analysis = self._analyze_block(case.body, audited=audited)
            continue_states.update(case_analysis.continue_states)
            bypass_nodes.extend(case_analysis.bypass_nodes)
        return _BlockAnalysis(
            continue_states=frozenset(continue_states),
            bypass_nodes=tuple(bypass_nodes),
        )

