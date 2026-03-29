"""PY-WL-004: Broad Exception Handlers.

Detects exception handlers that catch too broadly:

- ``except:`` — bare handler catches everything including SystemExit
- ``except Exception:`` — catches all standard exceptions
- ``except BaseException:`` — catches everything explicitly
- ``except*`` (TryStar) with broad types — Python 3.11+ exception groups
"""

from __future__ import annotations

import ast

from wardline.core.severity import RuleId
from wardline.scanner.rules.base import RuleBase, iter_exception_handlers, walk_skip_nested_defs

_BROAD_NAMES = frozenset({"Exception", "BaseException"})


class RulePyWl004(RuleBase):
    """Detect broad exception handlers.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_004

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-004 patterns."""
        for child in iter_exception_handlers(node):
            self._check_handler(child, node)
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call):
                self._check_suppress_call(child, node)

    def _check_handler(
        self,
        handler: ast.ExceptHandler,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Check a single ExceptHandler for broad exception patterns."""
        if self._is_immediate_reraise(handler):
            return
        if handler.type is None:
            # Bare except:
            self._emit_matrix_finding(
                handler,
                "Broad exception handler — bare 'except:' catches all "
                "exceptions including SystemExit and KeyboardInterrupt",
            )
            return

        name = self._resolve_broad_name(handler.type)
        if name is not None:
            self._emit_matrix_finding(
                handler,
                f"Broad exception handler — 'except {name}' catches "
                f"overly broad exception type",
            )

    def _check_suppress_call(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Detect ``contextlib.suppress(Exception)`` and imported ``suppress(Exception)``."""
        if not self._is_suppress_call(call):
            return
        for arg in call.args:
            if isinstance(arg, ast.expr) and self._resolve_broad_name(arg) is not None:
                self._emit_matrix_finding(
                    call,
                    "Broad exception handler — contextlib.suppress() suppresses "
                    "an overly broad exception type",
                )
                return

    @staticmethod
    def _is_immediate_reraise(handler: ast.ExceptHandler) -> bool:
        """Return True for handlers that immediately re-raise."""
        if len(handler.body) != 1:
            return False
        stmt = handler.body[0]
        if not isinstance(stmt, ast.Raise):
            return False
        if stmt.exc is None:
            return True
        return isinstance(stmt.exc, ast.Name) and stmt.exc.id == handler.name

    @staticmethod
    def _is_suppress_call(call: ast.Call) -> bool:
        """Return True for ``suppress(...)`` or ``contextlib.suppress(...)``."""
        if isinstance(call.func, ast.Name):
            return call.func.id == "suppress"
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "suppress"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "contextlib"
        )

    @staticmethod
    def _resolve_broad_name(node: ast.expr) -> str | None:
        """Return the broad exception name if node resolves to one, else None.

        Handles single names, qualified names (builtins.Exception),
        and tuples containing a broad member: ``except (Exception, ValueError):``.
        """
        if isinstance(node, ast.Name) and node.id in _BROAD_NAMES:
            return node.id
        if isinstance(node, ast.Attribute) and node.attr in _BROAD_NAMES:
            return node.attr
        if isinstance(node, ast.Tuple):
            for elt in node.elts:
                if isinstance(elt, ast.Name) and elt.id in _BROAD_NAMES:
                    return elt.id
                if (
                    isinstance(elt, ast.Attribute)
                    and elt.attr in _BROAD_NAMES
                ):
                    return elt.attr
        return None

