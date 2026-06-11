# src/wardline/scanner/rules/_sink_helpers.py
"""Shared helpers for the dangerous-sink rules (PY-WL-106/107/108).

A "sink rule" fires when raw-zone data reaches a named dangerous call (a
deserialization / dynamic-exec / OS-command sink) inside a trusted-tier function.
These helpers find the sink calls in a function's own scope, canonicalize their
names through the module import alias map, and resolve the taint of their arguments.

**Argument-taint resolution is FLOW-SENSITIVE.** Each sink call reads the engine's
per-call-site resolved argument taints (`function_call_site_arg_taints` — the taint of
every argument AT the sink line, produced by the L2 forward walk). The sink's worst
(least-trusted) argument taint drives the verdict, so a name reassigned raw→trusted
before the sink (or trusted→raw after an earlier sink) resolves at its taint at the call,
not the function's final map. When no call-site snapshot exists (an L2-skipped function),
resolution fails closed: a warning is emitted and any call with arguments is treated as
``UNKNOWN_RAW``.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.ast_primitives import fast_iter_child_nodes
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.rules.metadata import RuleMetadata

__all__ = [
    "RAW_ZONE",
    "TaintedSinkRule",
    "canonical_call_name",
    "dotted_name",
    "sink_calls",
    "worst_arg_taint",
]


def dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted call name: ``eval`` (Name) / ``pickle.loads`` (Attribute).

    Returns None when the receiver is not a pure Name/Attribute chain (e.g.
    ``get_ctx().eval`` — a Call receiver), so a dynamic attribute access can never be
    mistaken for a bare builtin sink like ``eval``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def canonical_call_name(dotted: str, alias_map: Mapping[str, str]) -> str:
    """Resolve a raw dotted call spelling through the module's import aliases.

    Handles ``import pickle as p; p.loads()``, ``from pickle import loads as l;
    l()``, and nested module aliases like ``import urllib.request as ur;
    ur.urlopen()``.
    """
    for local, target in sorted(alias_map.items(), key=lambda item: len(item[0]), reverse=True):
        if dotted == local:
            return target
        if dotted.startswith(local + "."):
            return f"{target}{dotted[len(local) :]}"
    return dotted


def _own_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Yield every ``ast.Call`` in *node*'s own analyzable scope.

    Function, async-function, and class bodies are indexed as their own entities, so
    they are not traversed here. Lambda bodies are intentionally traversed because
    the entity index does not emit separate lambda entities; skipping them would hide
    dangerous calls from sink rules.
    """
    for child in fast_iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Call):
            yield child
        yield from _own_calls(child)


def sink_calls(
    func_node: ast.AST,
    sink_names: frozenset[str],
    alias_map: Mapping[str, str] | None = None,
    module_prefix: str = "",
) -> Iterator[tuple[ast.Call, str]]:
    """Yield ``(call, dotted_name)`` for own-scope calls whose func resolves to a
    canonical name in *sink_names* (matches both ``eval`` and ``pickle.loads`` forms)."""
    from wardline.scanner.ast_primitives import resolve_call_fqn

    aliases = dict(alias_map or {})
    for call in _own_calls(func_node):
        fqn = resolve_call_fqn(call, aliases, frozenset(), module_prefix)
        if fqn is not None and fqn in sink_names:
            yield call, fqn
        else:
            dotted = dotted_name(call.func)
            if dotted is None:
                continue
            canonical = canonical_call_name(dotted, aliases)
            if canonical in sink_names:
                yield call, canonical


def _module_for_qualname(qualname: str, context: AnalysisContext) -> str | None:
    modules = context.alias_maps.keys()
    for module in sorted(modules, key=len, reverse=True):
        if qualname == module or qualname.startswith(module + "."):
            return module
    return None


def worst_arg_taint(call: ast.Call, qualname: str, context: AnalysisContext) -> TaintState | None:
    """The LEAST-trusted (highest TRUST_RANK) resolvable argument taint of *call*, or
    None when no argument resolves. Positional + keyword args are considered.

    Resolves from the engine's flow-sensitive per-call-site argument taints
    (``function_call_site_arg_taints`` — the resolved taint of each argument AT the call
    line). When no snapshot exists for *call* (an L2-skipped function), fails closed:
    warns and treats any call with arguments as ``UNKNOWN_RAW``."""
    # 1. Flow-sensitive resolved argument taints from L2 walk
    arg_taints_map = context.function_call_site_arg_taints.get(qualname, {}).get(id(call))
    if arg_taints_map is not None:
        worst_fs: TaintState | None = None
        for ts in arg_taints_map.values():
            if ts is not None and (worst_fs is None or TRUST_RANK[ts] > TRUST_RANK[worst_fs]):
                worst_fs = ts
        return worst_fs

    # Flow-sensitive snapshot is missing. Warn and enforce pessimistic default.
    import warnings

    warnings.warn(f"WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK: {qualname}", stacklevel=2)
    if call.args or call.keywords:
        return TaintState.UNKNOWN_RAW
    return None


class TaintedSinkRule:
    """Base for the dangerous-sink rules (106/107/108): raw-zone data reaching a named
    sink inside a trusted-tier function. Tier-MODULATED — silent in the developer-
    freedom zone (undecorated → UNKNOWN_RAW → modulate → NONE), speaking only where
    trust is declared (the same opt-in/fail-closed discipline as 103/104). Subclasses
    set ``rule_id``, ``metadata``, ``SINKS`` (the curated dotted sink names), and
    ``sink_label`` (for the message). Plain (not ClassVar) annotations so the instances
    satisfy the ``_Rule`` protocol (a settable instance ``rule_id``)."""

    rule_id: str
    metadata: RuleMetadata
    SINKS: frozenset[str]
    sink_label: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        missing = [a for a in ("rule_id", "metadata", "SINKS", "sink_label") if not hasattr(cls, a)]
        if missing:  # fail at import time, not at first check() — a config error in our own tree
            raise TypeError(f"{cls.__name__} must define class attribute(s): {', '.join(missing)}")

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or self.metadata.base_severity

    def _accept_call(self, call: ast.Call) -> bool:  # noqa: PLR6301
        """Extra per-call gate after the SINK-name match. Default: accept."""
        return True

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            lookup_name = qualname.split(".<locals>.")[0]
            tier = context.project_taints.get(lookup_name, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            module = _module_for_qualname(lookup_name, context)
            alias_map = context.alias_maps.get(module, {}) if module is not None else {}
            for call, dotted in sink_calls(entity.node, self.SINKS, alias_map, module or ""):
                if not self._accept_call(call):
                    continue
                worst = worst_arg_taint(call, qualname, context)
                if worst is None or worst not in RAW_ZONE:
                    continue
                line = call.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=(
                            f"{qualname}: {worst.value} (untrusted) data reaches the {self.sink_label} "
                            f"sink {dotted}() at line {line}"
                        ),
                        severity=severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            taint_path=f"{worst.value}->{dotted}",
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value, "sink": dotted, "arg_taint": worst.value},
                    )
                )
        return findings
