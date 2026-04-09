"""SUP-001: supplementary decorator contract enforcement.

Current scope intentionally focuses on local AST-checkable contracts:
- @parse_at_init call-site placement
- @atomic transaction wrapping
- @compensatable rollback discoverability/arity
- @deterministic bans, suppressed by @time_dependent
- @ordered_after shared call-site lexical ordering
- @not_reentrant local call-graph cycle detection
- @requires_identity audit threading
- @privileged_operation authorization-before-mutation
- @deprecated_by declaration-time expiry/advisory checks
- @feature_gated project-wide stale-flag detection
- @test_only production import bans for project-local decorated symbols
- @handles_secrets sink leak checks
- @handles_pii sink/error/persistence checks for declared fields
- @handles_classified downgrade checks
- @declassifies rejection-path and downgrade-shape checks

Residual non-goals for later slices:
- full sensitivity taint propagation across callers/returns and whole-program
  label tracking
- CODEOWNERS / protected-file governance for @declassifies
"""

from __future__ import annotations

import ast
from datetime import date

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, call_name, walk_skip_nested_defs

_ALLOWED_PARSE_CALLERS = ("__init__", "__post_init__", "setup")
_STATE_MUTATION_NAMES = frozenset({
    "add",
    "append",
    "commit",
    "create",
    "delete",
    "execute",
    "extend",
    "insert",
    "merge",
    "remove",
    "save",
    "update",
    "upsert",
    "write",
})
_TRANSACTION_HINTS = ("atomic", "transaction", "begin")
_AUTH_HINTS = (
    "allow",
    "auth",
    "authorize",
    "authorise",
    "can_",
    "check_permission",
    "permit",
    "require_permission",
    "require_role",
)
_IDENTITY_HINTS = (
    "actor",
    "identity",
    "principal",
    "subject",
    "user",
)
_TEST_PATH_PARTS = frozenset({"test", "tests", "testing"})
_FLAG_CHECK_HINTS = ("enabled", "feature", "flag", "gate", "toggle")
_LOG_SINK_HINTS = (
    "critical",
    "debug",
    "error",
    "exception",
    "info",
    "log",
    "logger",
    "print",
    "warn",
    "warning",
)
_PERSISTENCE_HINTS = (
    "commit",
    "create",
    "insert",
    "persist",
    "put",
    "save",
    "store",
    "update",
    "upsert",
    "write",
)
_PROTECTIVE_HINTS = ("bcrypt", "digest", "hash", "hmac", "mask", "redact", "scrub", "sha", "token")
_SECRET_NAME_HINTS = ("credential", "key", "password", "secret", "token")
_CLASSIFICATION_ORDER = {
    "OFFICIAL": 0,
    "PUBLIC": 0,
    "INTERNAL": 1,
    "PROTECTED": 2,
    "SECRET": 3,
    "TOP_SECRET": 4,
}


def _full_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _full_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _keyword_or_arg_name(call: ast.Call, keyword: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == keyword:
            return _full_name(kw.value)
    if (
        keyword == "name"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ):
        return call.args[0].value
    return None


def _is_state_mutating_call(call: ast.Call) -> bool:
    name = call_name(call)
    return name in _STATE_MUTATION_NAMES


def _is_transaction_context(node: ast.With | ast.AsyncWith) -> bool:
    return any(
        (ctx_name := _full_name(item.context_expr)) is not None
        and any(hint in ctx_name.lower() for hint in _TRANSACTION_HINTS)
        for item in node.items
    )


def _is_auth_call(call: ast.Call) -> bool:
    name = call_name(call)
    if name is None:
        return False
    lowered = name.lower()
    return any(hint in lowered for hint in _AUTH_HINTS)


def _is_nondeterministic_call(call: ast.Call) -> bool:
    full = _full_name(call.func)
    if full is None:
        return False
    lowered = full.lower()
    return lowered.startswith("random.") or lowered in {
        "uuid.uuid4",
        "datetime.now",
        "datetime.utcnow",
        "datetime.today",
        "date.today",
        "time.time",
    }


def _contains_hint(name: str, hints: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in hints)


def _call_matches_hints(call: ast.Call, hints: tuple[str, ...]) -> bool:
    full = _full_name(call.func)
    name = call_name(call)
    candidates = [value for value in (full, name) if value is not None]
    return any(_contains_hint(candidate, hints) for candidate in candidates)


def _is_log_sink(call: ast.Call) -> bool:
    return _call_matches_hints(call, _LOG_SINK_HINTS)


def _is_persistence_sink(call: ast.Call) -> bool:
    return _call_matches_hints(call, _PERSISTENCE_HINTS)


def _is_protective_call(call: ast.Call) -> bool:
    return _call_matches_hints(call, _PROTECTIVE_HINTS)


def _contains_sensitive_reference(
    expr: ast.AST,
    *,
    names: frozenset[str],
    fields: frozenset[str],
) -> bool:
    def _walk(node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and _is_protective_call(node):
            return False
        if isinstance(node, ast.Name) and node.id in names:
            return True
        if isinstance(node, ast.Attribute) and node.attr in fields:
            return True
        if isinstance(node, ast.Subscript):
            slice_node = node.slice
            if (
                isinstance(slice_node, ast.Constant)
                and isinstance(slice_node.value, str)
                and slice_node.value in fields
            ):
                return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in fields
        ):
            return True
        return any(_walk(child) for child in ast.iter_child_nodes(node))

    return _walk(expr)


def _terminates(stmt: ast.stmt) -> bool:
    if isinstance(stmt, (ast.Raise, ast.Return)):
        return True
    if isinstance(stmt, ast.If):
        return any(_terminates(child) for child in stmt.body) or any(
            _terminates(child) for child in stmt.orelse
        )
    if isinstance(stmt, ast.Match):
        return any(any(_terminates(child) for child in case.body) for case in stmt.cases)
    return False


def _has_rejection_path(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.If):
            if any(_terminates(child) for child in stmt.body):
                return True
            if any(_terminates(child) for child in stmt.orelse):
                return True
            if _has_rejection_path(stmt.body) or _has_rejection_path(stmt.orelse):
                return True
        if isinstance(stmt, ast.Match):
            for case in stmt.cases:
                if any(_terminates(child) for child in case.body):
                    return True
                if _has_rejection_path(case.body):
                    return True
    return False


def _classification_rank(level: object) -> int | None:
    if not isinstance(level, str):
        return None
    return _CLASSIFICATION_ORDER.get(level.upper())


class RuleSup001(RuleBase):
    """Enforce local supplementary-group contracts from the Python binding."""

    RULE_ID = RuleId.SUP_001

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path
        self._parse_at_init_targets: set[str] = set()
        self._audit_targets: set[str] = set()
        self._ordered_after: dict[str, str] = {}
        self._local_functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._local_calls: dict[str, set[str]] = {}
        self._module_name: str | None = None

    def visit_Module(self, node: ast.Module) -> None:
        self._parse_at_init_targets.clear()
        self._audit_targets.clear()
        self._ordered_after.clear()
        self._local_functions.clear()
        self._local_calls.clear()
        self._module_name = self._resolve_current_module_name()

        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._local_functions[child.name] = child
                self._local_calls[child.name] = {
                    name
                    for inner in walk_skip_nested_defs(child)
                    if isinstance(inner, ast.Call)
                    and (name := call_name(inner)) is not None
                }

        if self._context is not None and self._context.annotations_map is not None:
            for qualname, annotations in self._context.annotations_map.items():
                simple = qualname.rsplit(".", 1)[-1]
                for ann in annotations:
                    if ann.canonical_name == "parse_at_init":
                        self._parse_at_init_targets.add(simple)
                    elif ann.canonical_name in {"integral_writer", "integrity_critical"}:
                        self._audit_targets.add(simple)
                    elif ann.canonical_name == "ordered_after":
                        target = ann.attrs.get("name")
                        if isinstance(target, str):
                            self._ordered_after[simple] = target

        self._check_test_only_imports(node)
        self.generic_visit(node)

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        annotations = self._annotation_names()

        self._check_parse_at_init_calls(node)
        self._check_ordered_after(node)

        if "deterministic" in annotations and "time_dependent" not in annotations:
            self._check_deterministic(node)
        if "atomic" in annotations:
            self._check_atomic(node)
        if "compensatable" in annotations:
            self._check_compensatable(node)
        if "not_reentrant" in annotations:
            self._check_not_reentrant(node)
        if "requires_identity" in annotations:
            self._check_requires_identity(node)
        if "privileged_operation" in annotations:
            self._check_privileged_operation(node)
        if "deprecated_by" in annotations:
            self._check_deprecated_by(node)
        if "feature_gated" in annotations:
            self._check_feature_gated(node)
        if "handles_secrets" in annotations:
            self._check_handles_secrets(node)
        if "handles_pii" in annotations:
            self._check_handles_pii(node)
        if "handles_classified" in annotations:
            self._check_handles_classified(node)
        if "declassifies" in annotations:
            self._check_declassifies(node)

    def _resolve_current_module_name(self) -> str | None:
        if self._context is None or self._context.module_file_map is None:
            return None
        current = self._file_path
        for module_name, file_path in self._context.module_file_map.items():
            if file_path == current:
                return module_name
        return None

    def _is_test_file(self) -> bool:
        lowered_parts = {part.lower() for part in self._file_path.replace("\\", "/").split("/")}
        if lowered_parts & _TEST_PATH_PARTS:
            return True
        basename = self._file_path.rsplit("/", 1)[-1].lower()
        return basename.startswith("test_") or basename.endswith("_test.py")

    def _annotation_names(self) -> frozenset[str]:
        if self._context is None or self._context.annotations_map is None:
            return frozenset()
        return frozenset(
            ann.canonical_name
            for ann in self._context.annotations_map.get(self._current_qualname, ())
        )

    def _annotation_attr(self, name: str, attr: str) -> object | None:
        if self._context is None or self._context.annotations_map is None:
            return None
        for ann in self._context.annotations_map.get(self._current_qualname, ()):
            if ann.canonical_name == name:
                return ann.attrs.get(attr)
        return None

    def _project_annotation_names(self, file_path: str, symbol: str) -> frozenset[str]:
        if self._context is None or self._context.project_annotations_map is None:
            return frozenset()
        names = {
            ann.canonical_name
            for (ann_path, qualname), annotations in self._context.project_annotations_map.items()
            if ann_path == file_path and qualname.rsplit(".", 1)[-1] == symbol
            for ann in annotations
        }
        return frozenset(names)

    def _project_annotations(
        self,
        file_path: str,
        symbol: str,
    ) -> tuple[object, ...]:
        if self._context is None or self._context.project_annotations_map is None:
            return ()
        return tuple(
            ann
            for (ann_path, qualname), annotations in self._context.project_annotations_map.items()
            if ann_path == file_path and qualname.rsplit(".", 1)[-1] == symbol
            for ann in annotations
        )

    def _local_annotation_attr(
        self,
        symbol: str,
        annotation_name: str,
        attr: str,
    ) -> object | None:
        if self._context is None or self._context.annotations_map is None:
            return None
        for qualname, found_annotations in self._context.annotations_map.items():
            if qualname.rsplit(".", 1)[-1] != symbol:
                continue
            for ann in found_annotations:
                if ann.canonical_name == annotation_name:
                    return ann.attrs.get(attr)
        return None

    def _local_annotation_names(self, symbol: str) -> frozenset[str]:
        if self._context is None or self._context.annotations_map is None:
            return frozenset()
        return frozenset(
            ann.canonical_name
            for qualname, found_annotations in self._context.annotations_map.items()
            if qualname.rsplit(".", 1)[-1] == symbol
            for ann in found_annotations
        )

    def _resolve_import_module(self, node: ast.ImportFrom) -> str | None:
        if self._module_name is None:
            return node.module
        if node.level == 0:
            return node.module

        base_parts = self._module_name.split(".")
        current_is_package = self._file_path.endswith("__init__.py")
        package_parts = base_parts if current_is_package else base_parts[:-1]
        if node.level - 1 > len(package_parts):
            return None
        prefix = package_parts[: len(package_parts) - (node.level - 1)]
        suffix = [] if node.module is None else node.module.split(".")
        full_parts = [*prefix, *suffix]
        return ".".join(part for part in full_parts if part)

    def _check_test_only_imports(self, node: ast.Module) -> None:
        if self._is_test_file():
            return
        if self._context is None or self._context.module_file_map is None:
            return

        for child in node.body:
            if not isinstance(child, ast.ImportFrom):
                continue
            module_name = self._resolve_import_module(child)
            if not module_name:
                continue
            provider = self._context.module_file_map.get(module_name)
            if provider is None:
                continue
            for alias in child.names:
                if alias.name == "*":
                    continue
                if "test_only" in self._project_annotation_names(provider, alias.name):
                    self._emit(
                        child,
                        (
                            f"Production module imports @test_only symbol "
                            f"'{alias.name}' from '{module_name}'"
                        ),
                    )

    def _check_parse_at_init_calls(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        simple = self._current_qualname.rsplit(".", 1)[-1]
        if (
            simple == "__init__"
            or simple == "__post_init__"
            or simple.startswith("setup")
        ):
            return

        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            name = call_name(child)
            if name in self._parse_at_init_targets:
                self._emit(
                    child,
                    f"Call to @parse_at_init function '{name}' must stay in __init__, __post_init__, or setup methods",
                )

    def _check_deterministic(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call) and _is_nondeterministic_call(child):
                full = _full_name(child.func) or call_name(child) or "call"
                self._emit(
                    child,
                    f"@deterministic function calls non-deterministic API '{full}'",
                )

    def _check_atomic(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        unguarded: list[ast.Call] = []
        guarded: set[int] = set()

        for child in walk_skip_nested_defs(node):
            if isinstance(child, (ast.With, ast.AsyncWith)) and _is_transaction_context(child):
                for inner in walk_skip_nested_defs(ast.Module(body=child.body, type_ignores=[])):
                    if isinstance(inner, ast.Call) and _is_state_mutating_call(inner):
                        guarded.add(id(inner))

        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call) and _is_state_mutating_call(child) and id(child) not in guarded:
                unguarded.append(child)

        if len(unguarded) >= 2:
            self._emit(
                unguarded[1],
                "@atomic function has multiple state-modifying calls outside a transaction context",
            )

    def _check_compensatable(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        rollback_name = self._annotation_attr("compensatable", "rollback")
        if not isinstance(rollback_name, str):
            self._emit(
                node,
                "@compensatable requires a statically discoverable rollback function",
            )
            return

        rollback_def = self._local_functions.get(rollback_name)
        if rollback_def is None:
            self._emit(
                node,
                f"@compensatable rollback function '{rollback_name}' is not defined in this module",
            )
            return

        func_params = len(node.args.args)
        rollback_params = len(rollback_def.args.args)
        if rollback_params not in {1, func_params}:
            self._emit(
                node,
                (
                    f"@compensatable rollback '{rollback_name}' has "
                    f"incompatible arity ({rollback_params} params for "
                    f"{func_params}-param function)"
                ),
            )

    def _check_ordered_after(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        calls: dict[str, list[ast.Call]] = {}
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call):
                name = call_name(child)
                if name is not None:
                    calls.setdefault(name, []).append(child)

        for callee, predecessor in self._ordered_after.items():
            if callee not in calls or predecessor not in calls:
                continue
            if min(c.lineno for c in calls[predecessor]) > min(c.lineno for c in calls[callee]):
                self._emit(
                    calls[callee][0],
                    f"Calls to '{callee}' must be ordered after '{predecessor}' at shared call sites",
                )

    def _check_requires_identity(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        identity_params = {
            arg.arg
            for arg in node.args.args
            if any(hint in arg.arg.lower() for hint in _IDENTITY_HINTS)
        }
        if not identity_params:
            self._emit(
                node,
                "@requires_identity function has no identity-like parameter to thread into audit",
            )
            return

        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            callee_name = call_name(child)
            if callee_name not in self._audit_targets:
                continue
            arg_names = {
                name
                for expr in [*child.args, *(kw.value for kw in child.keywords if kw.arg is not None)]
                if (name := _full_name(expr)) is not None
            }
            if identity_params & arg_names:
                return

        self._emit(
            node,
            "@requires_identity function does not pass an identity parameter into an @integral_writer/@integrity_critical call",
        )

    def _check_not_reentrant(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        simple = self._current_qualname.rsplit(".", 1)[-1]
        stack = [simple]
        seen: set[str] = set()

        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for callee in self._local_calls.get(current, set()):
                if callee == simple:
                    self._emit(
                        node,
                        f"@not_reentrant function '{simple}' participates in a local call cycle",
                    )
                    return
                if callee in self._local_calls:
                    stack.append(callee)

    def _check_privileged_operation(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        auth_lines = [
            child.lineno
            for child in walk_skip_nested_defs(node)
            if isinstance(child, ast.Call) and _is_auth_call(child)
        ]
        mutation_calls = [
            child
            for child in walk_skip_nested_defs(node)
            if isinstance(child, ast.Call) and _is_state_mutating_call(child)
        ]
        if not mutation_calls:
            return
        if not auth_lines or min(auth_lines) > mutation_calls[0].lineno:
            self._emit(
                mutation_calls[0],
                "@privileged_operation requires an authorization check before the first state-modifying call",
            )

    def _check_deprecated_by(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        raw_date = self._annotation_attr("deprecated_by", "date")
        replacement = self._annotation_attr("deprecated_by", "replacement")
        if not isinstance(raw_date, str):
            self._emit(
                node,
                "@deprecated_by requires an ISO date string",
                severity=Severity.WARNING,
            )
            return

        try:
            expiry = date.fromisoformat(raw_date)
        except ValueError:
            self._emit(
                node,
                f"@deprecated_by date '{raw_date}' is not a valid ISO date",
                severity=Severity.WARNING,
            )
            return

        replacement_text = (
            f" Use '{replacement}' instead."
            if isinstance(replacement, str)
            else ""
        )
        today = date.today()
        if expiry < today:
            self._emit(
                node,
                f"@deprecated_by expiry {raw_date} has passed.{replacement_text}",
            )
        else:
            self._emit(
                node,
                f"@deprecated_by marks this symbol for deprecation on {raw_date}.{replacement_text}",
                severity=Severity.WARNING,
            )

    def _check_feature_gated(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        flag = self._annotation_attr("feature_gated", "flag")
        if not isinstance(flag, str) or not flag.strip():
            self._emit(
                node,
                "@feature_gated requires a non-empty flag name",
                severity=Severity.WARNING,
            )
            return

        project_count = 0
        if self._context is not None and self._context.string_literal_counts is not None:
            project_count = self._context.string_literal_counts.get(flag, 0)

        body_only = ast.Module(body=node.body, type_ignores=[])
        local_gate_reference = any(
            (
                isinstance(child, ast.Call)
                and (
                    (full := _full_name(child.func)) is not None
                    and any(hint in full.lower() for hint in _FLAG_CHECK_HINTS)
                    and any(
                        isinstance(arg, ast.Constant) and arg.value == flag
                        for arg in [*child.args, *(kw.value for kw in child.keywords)]
                    )
                )
            )
            or (
                isinstance(child, ast.Compare)
                and any(
                    isinstance(comp, ast.Constant) and comp.value == flag
                    for comp in [child.left, *child.comparators]
                )
            )
            for child in walk_skip_nested_defs(body_only)
        )
        if project_count <= 1 and not local_gate_reference:
            self._emit(
                node,
                (
                    f"@feature_gated flag '{flag}' appears stale: no static "
                    "references beyond the decorator were found"
                ),
                severity=Severity.WARNING,
            )

    def _secret_like_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> frozenset[str]:
        names = {
            arg.arg
            for arg in [*node.args.args, *node.args.kwonlyargs]
            if _contains_hint(arg.arg, _SECRET_NAME_HINTS)
        }
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Assign):
                continue
            if not isinstance(child.value, ast.Call):
                continue
            callee = call_name(child.value)
            if callee is None:
                continue
            ann_names = (
                self._local_annotation_names(callee)
                | self._project_annotation_names(self._file_path, callee)
            )
            if "handles_secrets" not in ann_names:
                continue
            for target in child.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        return frozenset(names)

    def _check_sensitive_sinks(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        names: frozenset[str],
        fields: frozenset[str],
        label: str,
    ) -> None:
        if not names and not fields:
            return

        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call) and (
                _is_log_sink(child) or _is_persistence_sink(child)
            ):
                values = [*child.args, *(kw.value for kw in child.keywords if kw.arg is not None)]
                if any(
                    _contains_sensitive_reference(value, names=names, fields=fields)
                    for value in values
                ):
                    sink = "logger/print sink" if _is_log_sink(child) else "persistence sink"
                    self._emit(
                        child,
                        f"{label} reaches a {sink} without protective transformation",
                    )
                    return
            if isinstance(child, ast.Raise) and child.exc is not None:
                payloads: list[ast.AST] = [child.exc]
                if isinstance(child.exc, ast.Call):
                    payloads.extend([*child.exc.args, *(kw.value for kw in child.exc.keywords if kw.arg is not None)])
                if any(
                    _contains_sensitive_reference(value, names=names, fields=fields)
                    for value in payloads
                ):
                    self._emit(
                        child,
                        f"{label} appears in an error message or exception payload",
                    )
                    return

    def _check_handles_secrets(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        names = self._secret_like_names(node)
        self._check_sensitive_sinks(
            node,
            names=names,
            fields=frozenset(),
            label="Secret-bearing data",
        )

    def _check_handles_pii(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        raw_fields = self._annotation_attr("handles_pii", "fields")
        fields = frozenset(
            value
            for value in raw_fields
            if isinstance(value, str)
        ) if isinstance(raw_fields, tuple) else frozenset()
        if not fields:
            self._emit(
                node,
                "@handles_pii requires at least one statically discoverable field name",
                severity=Severity.WARNING,
            )
            return
        param_names = frozenset(arg.arg for arg in [*node.args.args, *node.args.kwonlyargs])
        self._check_sensitive_sinks(
            node,
            names=param_names & fields,
            fields=fields,
            label="PII field",
        )

    def _check_handles_classified(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        level = self._annotation_attr("handles_classified", "level")
        level_rank = _classification_rank(level)
        if level_rank is None:
            self._emit(
                node,
                "@handles_classified requires a known classification level",
                severity=Severity.WARNING,
            )
            return

        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            callee = call_name(child)
            if callee is None:
                continue

            callee_level = self._local_annotation_attr(callee, "handles_classified", "level")
            callee_rank = _classification_rank(callee_level)
            if callee_rank is not None and callee_rank < level_rank:
                declass_from = self._local_annotation_attr(callee, "declassifies", "from_level")
                declass_to = self._local_annotation_attr(callee, "declassifies", "to_level")
                if declass_from == level and _classification_rank(declass_to) == callee_rank:
                    continue
                self._emit(
                    child,
                    (
                        f"@handles_classified(level={level}) calls lower-classification "
                        f"function '{callee}' (level={callee_level}) without @declassifies"
                    ),
                )
                return

    def _check_declassifies(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        from_level = self._annotation_attr("declassifies", "from_level")
        to_level = self._annotation_attr("declassifies", "to_level")
        from_rank = _classification_rank(from_level)
        to_rank = _classification_rank(to_level)
        if from_rank is None or to_rank is None:
            self._emit(
                node,
                "@declassifies requires known from_level/to_level values",
                severity=Severity.WARNING,
            )
            return
        if to_rank >= from_rank:
            self._emit(
                node,
                (
                    f"@declassifies must lower classification, but {from_level} -> "
                    f"{to_level} is not a downgrade"
                ),
            )
        if not _has_rejection_path(node.body):
            self._emit(
                node,
                "@declassifies body must contain a rejection path (raise/return branch)",
            )

    def _emit(self, node: ast.AST, message: str, *, severity: Severity = Severity.ERROR) -> None:
        self.findings.append(
            Finding(
                rule_id=self.RULE_ID,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=message,
                severity=severity,
                exceptionability=Exceptionability.STANDARD,
                taint_state=self._get_function_taint(self._current_qualname),
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
                annotation_groups=self._get_annotation_groups(),
            )
        )
