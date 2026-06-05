# src/wardline/scanner/rules/none_leak.py
"""PY-WL-109 — None leaks from a trusted producer.

Fires on an anchored trusted producer whose **return annotation promises a non-None
type** yet a path yields ``None`` (a bare ``return`` or ``return None``) alongside a
value-bearing return — a PROVABLE contract violation: the function declares ``-> T``
(non-None) but leaks ``None`` (CWE-394 / a latent None-deref downstream).

Declaration-gated (base WARN). FP-guarded — the annotation is the load-bearing guard:
  - **requires an explicit non-None return annotation** (``-> T``). A function with NO
    annotation, or one declaring ``Optional[T]`` / ``T | None`` / ``-> None`` /
    ``-> Any``, does NOT fire — that is a deliberately-nullable, dynamic, or unstated
    contract, not a leak. This is what keeps the rule off the single most common
    legitimate pattern (``Optional`` returns), per the FP-economics review;
  - requires BOTH a value-bearing return AND a None-yielding return in scope;
  - **skips generators** (a bare ``return`` ends iteration — not a None value leak);
  - skips the trust-RAISING shape (body less trusted than declared — ``@trust_boundary``'s
    territory, policed by PY-WL-102), mirroring PY-WL-101's delegation.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TRUST_RANK
from wardline.scanner.rules._ast_helpers import _own_statements
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-109",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "A trusted producer has both a value-bearing return and a None-yielding return "
        "(bare return / return None) — None leaks from a function declaring trusted output."
    ),
    examples_violation=(
        "@trusted(level='ASSURED')\ndef f(flag) -> int:\n    if flag:\n        return g()\n    return",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(flag) -> int | None:\n    if flag:\n        return g()\n    return None",
    ),
)


def _module_for_qualname(qualname: str, context: AnalysisContext) -> str | None:
    modules = context.alias_maps.keys()
    for module in sorted(modules, key=len, reverse=True):
        if qualname == module or qualname.startswith(module + "."):
            return module
    return None


def _is_none_return(stmt: ast.Return) -> bool:
    """A bare ``return`` (value is None) or an explicit ``return None``."""
    return stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)


def _annotation_allows_none(ann: ast.expr, alias_map: Mapping[str, str] | None = None) -> bool:
    """True if a return annotation does not promise non-None: bare ``None``,
    ``Any``, ``Optional[...]``, or a ``... | None`` union (recursively)."""
    if isinstance(ann, ast.Constant) and ann.value is None:
        return True
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        try:
            parsed = ast.parse(ann.value, mode="eval")
            return _annotation_allows_none(parsed.body, alias_map)
        except SyntaxError:
            return False
    if isinstance(ann, ast.Name) and ann.id == "None":
        return True

    fqn: str | None = None
    if isinstance(ann, ast.Name):
        fqn = alias_map.get(ann.id) if alias_map else None
        if not fqn:
            fqn = ann.id
    elif isinstance(ann, ast.Attribute) and isinstance(ann.value, ast.Name):
        base = alias_map.get(ann.value.id) if alias_map else None
        fqn = f"{base}.{ann.attr}" if base else f"{ann.value.id}.{ann.attr}"

    if fqn in ("typing.Any", "Any"):
        return True
    if fqn in ("typing.Optional", "Optional"):
        return True

    if isinstance(ann, ast.Subscript):  # Optional[X] / Union[X, None]
        ann_base = ann.value
        base_fqn: str | None = None
        if isinstance(ann_base, ast.Name):
            base_fqn = alias_map.get(ann_base.id) if alias_map else None
            if not base_fqn:
                base_fqn = ann_base.id
        elif isinstance(ann_base, ast.Attribute) and isinstance(ann_base.value, ast.Name):
            b_base = alias_map.get(ann_base.value.id) if alias_map else None
            base_fqn = f"{b_base}.{ann_base.attr}" if b_base else f"{ann_base.value.id}.{ann_base.attr}"

        if base_fqn in ("typing.Optional", "Optional"):
            return True
        if base_fqn in ("typing.Union", "Union"):
            sl = ann.slice
            # Handle ast.Index wrapper on older Python versions (e.g. <3.9)
            if hasattr(ast, "Index") and isinstance(sl, ast.Index):
                sl = sl.value  # type: ignore
            if isinstance(sl, ast.Tuple):
                return any(_annotation_allows_none(elt, alias_map) for elt in sl.elts)
            return _annotation_allows_none(sl, alias_map)

    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):  # X | None
        return _annotation_allows_none(ann.left, alias_map) or _annotation_allows_none(ann.right, alias_map)
    return False


def _promises_non_none(
    node: ast.FunctionDef | ast.AsyncFunctionDef, alias_map: Mapping[str, str] | None = None
) -> bool:
    """True iff the function has an explicit return annotation that does NOT permit
    None — the provable non-None contract 109 polices. No annotation → False."""
    return node.returns is not None and not _annotation_allows_none(node.returns, alias_map)


def _is_generator(node: ast.AST) -> bool:
    """True if *node*'s own scope contains a ``yield``/``yield from`` (does not descend
    into nested def/class/lambda — those are separate scopes)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, (ast.Yield, ast.YieldFrom)) or _is_generator(child):
            return True
    return False


def _can_fall_through(stmts: list[ast.stmt]) -> bool:
    """True if there is any execution path through stmts that doesn't end with return or raise."""
    if not stmts:
        return True
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return False
        if isinstance(stmt, ast.If):
            if not stmt.orelse:
                # If can fall through if condition is false
                pass
            else:
                body_falls = _can_fall_through(stmt.body)
                else_falls = _can_fall_through(stmt.orelse)
                if not body_falls and not else_falls:
                    return False
        if isinstance(stmt, ast.Try):
            if stmt.finalbody and not _can_fall_through(stmt.finalbody):
                return False
            normal_falls = _can_fall_through(stmt.body)
            normal_terminal = not normal_falls or (bool(stmt.orelse) and not _can_fall_through(stmt.orelse))
            handlers_terminal = all(not _can_fall_through(handler.body) for handler in stmt.handlers)
            if normal_terminal and handlers_terminal:
                return False
        if isinstance(stmt, ast.Match):
            has_wildcard = any(
                isinstance(case.pattern, ast.MatchAs)
                and case.pattern.pattern is None
                and case.pattern.name is None
                and case.guard is None
                for case in stmt.cases
            )
            if has_wildcard and all(not _can_fall_through(case.body) for case in stmt.cases):
                return False
    return True


class NoneLeak:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            declared = context.project_return_taints.get(qualname)
            if declared is None or declared in RAW_ZONE:
                continue  # trust-claim gate (same as PY-WL-101)
            body = context.project_taints.get(qualname)
            if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
                continue  # trust-raising shape -> PY-WL-102's territory, not 109's
            if _is_generator(entity.node):
                continue
            module = _module_for_qualname(qualname, context)
            alias_map = context.alias_maps.get(module, {}) if module is not None else {}
            if not _promises_non_none(entity.node, alias_map):
                continue  # no explicit non-None contract -> not a provable leak (FP guard)
            has_value = False
            has_none = _can_fall_through(entity.node.body)
            for stmt in _own_statements(entity.node):
                if isinstance(stmt, ast.Return):
                    if _is_none_return(stmt):
                        has_none = True
                    else:
                        has_value = True
            if not (has_value and has_none):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares trusted return {declared.value} but a path returns None "
                        f"(bare return / return None) — None leaks from a trusted producer"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=f"None->{declared.value}",
                    ),
                    qualname=qualname,
                    properties={"declared_return": declared.value},
                )
            )
        return findings
