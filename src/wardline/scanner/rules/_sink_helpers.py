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
    "enclosing_declared_tier",
    "resolved_arg_taints",
    "sink_calls",
    "sink_method_calls",
    "worst_arg_taint",
]


def enclosing_declared_tier(
    qualname: str,
    project_taints: Mapping[str, TaintState],
    declared_qualnames: frozenset[str],
) -> TaintState:
    """Trust tier governing *qualname*, honoring a nested def's OWN trust decorator.

    Walks outward through ``.<locals>.`` enclosing scopes and returns the tier of the
    nearest scope that carries an explicit trust DECLARATION (``declared_qualnames`` — the
    trust surface). So a nested def with its own decorator uses its own tier
    (wardline-bb8396f96e), while a genuinely undeclared nested def inherits the nearest
    declared enclosing scope's tier (wardline-9b88ec5419). Falls back to the full qualname's
    own tier (defaulting ``UNKNOWN_RAW`` → developer-freedom) when no scope in the lexical
    chain is declared.

    Keying off the explicit-declaration set — not a tier heuristic — is what distinguishes
    "this def declared its own trust" from "this def is undeclared and should inherit": an
    undeclared nested def is registered in ``project_taints`` (typically ``UNKNOWN_RAW``) yet
    is absent from ``declared_qualnames``, so the walk correctly steps past it to the parent.
    """
    parts = qualname.split(".<locals>.")
    for i in range(len(parts), 0, -1):
        candidate = ".<locals>.".join(parts[:i])
        if candidate in declared_qualnames:
            return project_taints.get(candidate, TaintState.UNKNOWN_RAW)
    return project_taints.get(qualname, TaintState.UNKNOWN_RAW)


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
    for child in ast.iter_child_nodes(node):
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


def sink_method_calls(func_node: ast.AST, method_names: frozenset[str]) -> Iterator[ast.Call]:
    """Yield own-scope calls whose func is an attribute access ``recv.<method>`` whose method
    name is in *method_names* (e.g. ``cursor.execute``).

    Descends into lambda bodies (via :func:`_own_calls`) so a sink wrapped in a lambda is not
    missed — the same lambda-traversal the dotted-FQN :func:`sink_calls` path already has; does
    not enter nested def/class scopes (those are indexed as their own entities). For rules that
    key on the METHOD NAME regardless of receiver (PY-WL-118), as opposed to canonical dotted
    sink FQNs."""
    for call in _own_calls(func_node):
        if isinstance(call.func, ast.Attribute) and call.func.attr in method_names:
            yield call


def _module_for_qualname(qualname: str, context: AnalysisContext) -> str | None:
    modules = context.alias_maps.keys()
    for module in sorted(modules, key=len, reverse=True):
        if qualname == module or qualname.startswith(module + "."):
            return module
    return None


def resolved_arg_taints(call: ast.Call, qualname: str, context: AnalysisContext) -> dict[int | str | None, TaintState]:
    """Per-argument resolved taints for *call* — THE single fail-closed argument resolver.

    Returns the engine's flow-sensitive per-call-site snapshot
    (``function_call_site_arg_taints`` — the resolved taint of each argument AT the call
    line), keyed by positional index (``int``), keyword name (``str``), ``None``
    (``**kwargs``), and a ``"*{i}"`` marker alongside the int key for a ``Starred``
    positional. Empty dict when the call takes no arguments.

    Fail-closed: when no L2 snapshot exists for *call* (an L2-skipped function), warns
    ``WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK`` and returns a pessimistic map marking every
    syntactic argument ``UNKNOWN_RAW``. Each rule then SELECTS over this result on its own
    terms (worst / any-provably-untrusted / by-position), so the fail-closed contract lives
    in exactly one place and cannot drift between rules. The pessimism is correctly
    direction-aware: a RAW_ZONE-gate (sink rules / a SQL-string position) still fires on the
    UNKNOWN_RAW fallback, while a *provably*-untrusted gate (PY-WL-105, which excludes
    UNKNOWN_RAW) correctly stays silent — preserving its deliberate no-flood design."""
    snapshot = context.function_call_site_arg_taints.get(qualname, {}).get(id(call))
    if snapshot is not None:
        return dict(snapshot)

    # Flow-sensitive snapshot is missing. Warn and build a pessimistic per-arg map.
    import warnings

    warnings.warn(f"WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK: {qualname}", stacklevel=2)
    pessimistic: dict[int | str | None, TaintState] = {}
    for i, arg in enumerate(call.args):
        pessimistic[i] = TaintState.UNKNOWN_RAW
        if isinstance(arg, ast.Starred):
            pessimistic[f"*{i}"] = TaintState.UNKNOWN_RAW
    for kw in call.keywords:
        pessimistic[kw.arg] = TaintState.UNKNOWN_RAW
    return pessimistic


def worst_arg_taint(call: ast.Call, qualname: str, context: AnalysisContext) -> TaintState | None:
    """The LEAST-trusted (highest TRUST_RANK) resolvable argument taint of *call*, or
    None when no argument resolves. Positional + keyword args are considered.

    Thin selector over :func:`resolved_arg_taints` (the shared fail-closed resolver):
    when no snapshot exists, that resolver yields a pessimistic ``UNKNOWN_RAW`` per arg,
    so a call with arguments still resolves to ``UNKNOWN_RAW`` (fail-closed)."""
    worst: TaintState | None = None
    for ts in resolved_arg_taints(call, qualname, context).values():
        if ts is not None and (worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]):
            worst = ts
    return worst


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
            # Honor a nested def's OWN trust decorator, else inherit the nearest declared
            # enclosing scope's tier (wardline-bb8396f96e / wardline-9b88ec5419).
            tier = enclosing_declared_tier(qualname, context.project_taints, context.declared_qualnames)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # freedom / fail-closed zone — suppressed
            module = _module_for_qualname(qualname, context)
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
                            qualname=qualname,
                            # Call-site-anchored: >1 finding per (rule, path, qualname) is possible
                            # (several sinks in one function). Discriminate by SOURCE only — an
                            # ENTITY-RELATIVE line offset (call line - the enclosing def's line, invariant
                            # to a comment ABOVE the function: wlfp2/wardline-8654423823) plus the call's
                            # full lexical SPAN and the sink dotted-name. The span (start:end), not the
                            # start column alone, separates the outer/inner calls of a chain
                            # (``a.sink(x).sink(y)``), which share a start column. Never the resolved arg
                            # taint (it drifts across builds: weft-4a9d0f863c).
                            taint_path=f"{line - (entity.location.line_start or 0)}:{call.col_offset}:{call.end_col_offset}:{dotted}",  # noqa: E501
                        ),
                        # OLD (wlfp1) taint_path, byte-exact, for `wardline rekey` (P4).
                        taint_path_v0=f"{dotted}@{call.col_offset}:{call.end_col_offset}",
                        qualname=qualname,
                        properties={"tier": tier.value, "sink": dotted, "arg_taint": worst.value},
                    )
                )
        return findings
