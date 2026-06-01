# src/wardline/scanner/taint/decorator_provider.py
"""The real taint-source provider: seeds L1 taints from the trust vocabulary.

Reads ``@external_boundary`` / ``@trust_boundary`` / ``@trusted`` off each
function's AST decorator list (resolving import aliases via
``SeedContext.alias_map``) and maps them to ``FunctionTaint``. Replaces
``DefaultTaintSourceProvider`` as ``WardlineAnalyzer``'s default. An undecorated
function — or any decorator whose level cannot be read statically or is outside
the allowed set — gets *no opinion* (``None``), so the engine falls back to the
unchanged fail-closed ``UNKNOWN_RAW`` L1 precedence.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.registry import REGISTRY, REGISTRY_VERSION
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.taint.provider import FunctionTaint

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.index import Entity
    from wardline.scanner.taint.provider import SeedContext

_VOCAB_PREFIX = "wardline.decorators"
_TAINTSTATE_FQN = "wardline.core.taints.TaintState"
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted name (``a.b.c``) from a Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _resolve_dotted_fqn(node: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    """Reconstruct ``node``'s dotted name and rewrite its head via ``alias_map``.

    Returns None for non-name nodes (calls, subscripts, literals).
    """
    dotted = _dotted_name(node)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    head_fqn = alias_map.get(head, head)
    return f"{head_fqn}.{rest}" if rest else head_fqn


def _resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    """Resolve a decorator node to a fully-qualified name via the alias map.

    Strips a call wrapper (``@d(...)`` -> ``d``) then resolves the dotted name.
    """
    func = deco.func if isinstance(deco, ast.Call) else deco
    return _resolve_dotted_fqn(func, alias_map)


def _level_token(value: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    """Extract a TaintState name token from a keyword-argument value node.

    Handles a string literal (``"ASSURED"``) and an attribute access whose
    receiver alias-resolves to ``wardline.core.taints.TaintState`` (so
    ``TaintState.ASSURED`` -> ``"ASSURED"``, but a coincidental ``cfg.ASSURED``
    is rejected). Anything else (a bare Name, a call, an f-string, a non-
    ``TaintState`` attribute) is not statically readable -> None (fail-closed).
    """
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute):
        if _resolve_dotted_fqn(value.value, alias_map) == _TAINTSTATE_FQN:
            return value.attr
        return None
    return None


def _read_level(
    deco: ast.expr,
    arg: str,
    *,
    allowed: frozenset[TaintState],
    default: TaintState | None,
    alias_map: Mapping[str, str],
) -> TaintState | None:
    """Read a level keyword arg from a decorator, normalised + allow-checked.

    Returns ``default`` when the decorator is not called or the arg is absent;
    ``None`` (fail-closed) when the arg is present but unreadable, an invalid
    state, or outside ``allowed``. Positional args are intentionally ignored —
    the real decorators are keyword-only, so a positional form is malformed
    source and reads as ``default`` (fail-closed for required-arg decorators).
    """
    if not isinstance(deco, ast.Call):
        return default
    for kw in deco.keywords:
        if kw.arg == arg:
            token = _level_token(kw.value, alias_map)
            if token is None:
                return None
            try:
                level = TaintState(token)
            except ValueError:
                return None
            return level if level in allowed else None
    return default


class DecoratorTaintSourceProvider:
    """Seeds taints from the generic trust-decorator vocabulary (SP2)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        candidates: list[FunctionTaint] = []
        for deco in entity.node.decorator_list:
            ft = self._match(deco, ctx.alias_map)
            if ft is not None:
                candidates.append(ft)
        if not candidates:
            return None
        # Multiple trust decorators on one function is an authoring conflict; take
        # the LEAST-trusted value PER FIELD independently (highest TRUST_RANK) so
        # contradictory annotations can never over-trust either the body or the
        # return. Order-independent (the per-field max does not depend on
        # candidate order, even on a return-rank tie).
        body = max((ft.body_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        ret = max((ft.return_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        return FunctionTaint(body, ret)

    def fingerprint(self) -> str:
        return f"decorator-vocab:{REGISTRY_VERSION}"

    def _match(self, deco: ast.expr, alias_map: Mapping[str, str]) -> FunctionTaint | None:
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None or not fqn.startswith(_VOCAB_PREFIX + "."):
            return None
        canonical = fqn.rsplit(".", 1)[-1]
        if canonical not in REGISTRY:
            return None
        if canonical == "external_boundary":
            return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)
        if canonical == "trust_boundary":
            to_level = _read_level(deco, "to_level", allowed=_BOUNDARY_LEVELS, default=None, alias_map=alias_map)
            if to_level is None:
                return None
            return FunctionTaint(TaintState.EXTERNAL_RAW, to_level)
        if canonical == "trusted":
            level = _read_level(
                deco,
                "level",
                allowed=_TRUSTED_LEVELS,
                default=TaintState.INTEGRAL,
                alias_map=alias_map,
            )
            if level is None:
                return None
            return FunctionTaint(level, level)
        return None
