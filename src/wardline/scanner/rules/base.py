"""RuleBase — abstract base class for all wardline scanner rules.

All rules subclass RuleBase and implement ``visit_function``. The
``visit_FunctionDef`` and ``visit_AsyncFunctionDef`` methods are
``@typing.final`` and delegate to ``visit_function`` — subclasses
must not override them. ``__init_subclass__`` enforces this at
class definition time (runtime), ``@typing.final`` enforces it
statically (mypy).
"""

from __future__ import annotations

import ast
import logging
from abc import ABC, abstractmethod
from collections import deque
from typing import TYPE_CHECKING, ClassVar, final

from wardline.core import matrix
from wardline.core.taints import TaintState
from wardline.scanner.context import Finding

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wardline.core.severity import RuleId
    from wardline.scanner.context import ScanContext

_GUARDED_METHODS = frozenset({"visit_FunctionDef", "visit_AsyncFunctionDef"})


# ── Shared AST helpers ──────────────────────────────────────────

def walk_skip_nested_defs(node: ast.AST) -> Iterator[ast.AST]:
    """Like ``ast.walk`` but skip nested FunctionDef/AsyncFunctionDef bodies.

    The root *node* is always yielded. Child nodes that are
    ``FunctionDef`` or ``AsyncFunctionDef`` (and are not the root) are
    skipped entirely — the base class ``generic_visit`` handles those
    separately, so descending here would cause duplicate findings.
    """
    todo: deque[ast.AST] = deque([node])
    while todo:
        current = todo.popleft()
        yield current
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                continue
            todo.append(child)


def decorator_name(node: ast.expr) -> str | None:
    """Return the terminal decorator name for ``@name`` and ``@pkg.name``.

    Handles both bare decorators (``@foo``) and call decorators
    (``@foo(...)``). Returns ``None`` for complex expressions.
    """
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def call_name(call: ast.Call) -> str | None:
    """Return the bare or terminal attribute name for a call target."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def receiver_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an expression for receiver matching.

    Returns the name for ``ast.Name`` (e.g. ``"jsonschema"``) or the
    full dotted chain for ``ast.Attribute`` (e.g. ``"json.loads"``).
    Returns ``None`` for complex expressions.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = receiver_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def iter_exception_handlers(node: ast.AST) -> Iterator[ast.ExceptHandler]:
    """Yield all ExceptHandler nodes under *node*, skipping nested defs."""
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.ExceptHandler):
            yield child


# ── RuleBase ────────────────────────────────────────────────────

class RuleBase(ast.NodeVisitor, ABC):
    """Abstract base for all wardline scanner rules.

    Concrete rules must:
    - Subclass RuleBase directly
    - Set ``RULE_ID`` class variable to the canonical ``RuleId``
    - Implement ``visit_function(node, is_async)``
    - NOT override ``visit_FunctionDef`` or ``visit_AsyncFunctionDef``
    """

    RULE_ID: ClassVar[RuleId]

    def __init__(self) -> None:
        super().__init__()
        self.findings: list[Finding] = []
        self._file_path: str = ""
        self._context: ScanContext | None = None
        self._scope_stack: list[str] = []
        self._current_qualname: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Call super BEFORE our check — required for cooperative MRO
        super().__init_subclass__(**kwargs)

        for method_name in _GUARDED_METHODS:
            if method_name in cls.__dict__:
                raise TypeError(
                    f"{cls.__name__} must not override {method_name}. "
                    f"Implement visit_function() instead."
                )

        # Validate RULE_ID is defined on concrete rule subclasses.
        # Skip abstract classes (those that still have abstractmethod).
        has_abstract = any(
            getattr(getattr(cls, name, None), "__isabstractmethod__", False)
            for name in dir(cls)
        )
        if not has_abstract and "RULE_ID" not in cls.__dict__:
            raise TypeError(
                f"{cls.__name__} must define a RULE_ID class variable."
            )

    @final
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Dispatch sync function to visit_function. Do not override."""
        self._dispatch(node, is_async=False)

    @final
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Dispatch async function to visit_function. Do not override."""
        self._dispatch(node, is_async=True)

    def set_context(self, ctx: ScanContext | None) -> None:
        """Set (or clear) the per-file scan context.

        Also syncs ``_file_path`` and resets scope tracking state so
        ScanContext is the single authoritative source of per-file state.
        Resetting the scope stack here ensures that a crash during a
        previous file's traversal cannot corrupt qualnames for this file.
        """
        self._context = ctx
        self._file_path = ctx.file_path if ctx is not None else ""
        self._scope_stack.clear()
        self._current_qualname = ""

    def _get_function_taint(self, qualname: str) -> TaintState:
        """Look up the taint state for *qualname* in the current context.

        Returns ``UNKNOWN_RAW`` when no context is set or the qualname
        is not present in the taint map.
        """
        if self._context is None:
            return TaintState.UNKNOWN_RAW
        taint = self._context.function_level_taint_map.get(qualname)
        if taint is None:
            logger.debug(
                "Taint map miss for qualname %r in %s",
                qualname, self._file_path,
            )
            return TaintState.UNKNOWN_RAW
        return taint

    def _emit_matrix_finding(self, node: ast.AST, message: str) -> None:
        """Emit a finding using the severity matrix for ``self.RULE_ID``.

        Looks up the (rule, taint) severity cell and appends a Finding
        with standard location extraction from *node*.
        """
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=self.RULE_ID,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=message,
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )

    def _dispatch(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
    ) -> None:
        """Dispatch to visit_function, then recurse into nested defs.

        The scope stack push happens before visit_function so that
        ``self._current_qualname`` is correct during rule execution.
        The pop happens AFTER generic_visit so that nested functions
        see the enclosing function on the scope stack.  try/finally
        guarantees the pop even if visit_function raises.
        """
        self._current_qualname = ".".join([*self._scope_stack, node.name])
        self._scope_stack.append(node.name)
        try:
            self.visit_function(node, is_async=is_async)
            self.generic_visit(node)
        finally:
            self._scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class scope for qualname construction."""
        self._scope_stack.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._scope_stack.pop()

    @abstractmethod
    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Visit a function definition. Implement in subclasses.

        Findings should be appended to an instance-level collection.
        The ``is_async`` flag distinguishes sync from async functions
        without requiring isinstance checks in every rule.
        """
        ...
