# src/wardline/scanner/rules/invalid_decorator_level.py
"""PY-WL-114 — builtin trust decorator whose level is statically readable but invalid or out-of-range.

Fires on any entity carrying a builtin trust decorator (@trusted or @trust_boundary)
where the level argument is statically readable but not a valid TaintState or not within
the decorator's allowed set. This is a critical safety defect: a typo (e.g. 'ASURED')
causes the engine to silently drop the decorator, disabling all taint gates on that function.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TaintState
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})

METADATA = RuleMetadata(
    rule_id="PY-WL-114",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A builtin trust decorator (@trusted or @trust_boundary) has a level argument "
        "that is statically readable but invalid or out-of-range."
    ),
    examples_violation=(
        "@trusted(level='ASURED')\ndef f(p):\n    return p",
        "@trust_boundary(to_level='INTEGRAL')\ndef g(p):\n    if not p: raise ValueError\n    return p",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef g(p):\n    if not p: raise ValueError\n    return p",
        "@trusted(level=cfg.LEVEL)\ndef h(p):\n    return p",
    ),
)


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted name (a.b.c) from a Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _level_token(value: ast.expr) -> str | None:
    """Extract a level token from a Constant string or an Attribute name."""
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute):
        base = _dotted_name(value.value)
        if base is not None and (base == "TaintState" or base.endswith(".TaintState")):
            return value.attr
    return None


def _marker_name(deco: ast.expr) -> str | None:
    """The trailing identifier of a decorator (e.g. trusted or trust_boundary)."""
    node = deco.func if isinstance(deco, ast.Call) else deco
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


class InvalidDecoratorLevel:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            for deco in entity.node.decorator_list:
                name = _marker_name(deco)
                if name not in ("trusted", "trust_boundary"):
                    continue

                if not isinstance(deco, ast.Call):
                    continue

                # For trusted, check keyword 'level'
                # For trust_boundary, check keyword 'to_level'
                target_kw = "level" if name == "trusted" else "to_level"
                allowed_set = _TRUSTED_LEVELS if name == "trusted" else _BOUNDARY_LEVELS

                for kw in deco.keywords:
                    if kw.arg != target_kw:
                        continue

                    token = _level_token(kw.value)
                    if token is None:
                        continue  # not statically readable (e.g. dynamic variable)

                    is_invalid = False
                    try:
                        level = TaintState(token)
                        if level not in allowed_set:
                            is_invalid = True
                    except ValueError:
                        is_invalid = True

                    if is_invalid:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                message=(
                                    f"{qualname} has an invalid or out-of-range trust level "
                                    f"{token!r} on decorator @{name}"
                                ),
                                severity=self.base_severity,
                                kind=Kind.DEFECT,
                                location=entity.location,
                                fingerprint=_fp(
                                    rule_id=self.rule_id,
                                    path=entity.location.path,
                                    line_start=entity.location.line_start,
                                    qualname=qualname,
                                    taint_path=f"{name}:{token}",
                                ),
                                qualname=qualname,
                                properties={"decorator": name, "token": token},
                            )
                        )
        return findings
