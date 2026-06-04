# src/wardline/scanner/rules/_sink_helpers.py
"""Shared helpers for the dangerous-sink rules (PY-WL-106/107/108).

A "sink rule" fires when raw-zone data reaches a named dangerous call (a
deserialization / dynamic-exec / OS-command sink) inside a trusted-tier function.
These helpers find the sink calls in a function's own scope, canonicalize their
names through the module import alias map, and resolve the taint of their arguments.

**Argument-taint resolution is FLOW-INSENSITIVE.** A rule reads the engine's RESOLVED
state post-hoc, where only the FINAL per-variable taint map (`function_var_taints`) is
available. So:
  - ``ast.Name`` arg  → its final var taint, or skip if the name is unknown (a global /
    free / builtin name not in the var map);
  - same-module bare ``ast.Call`` arg (``sink(read_raw(p))``) → the callee's resolved
    return taint, if the callee resolves to a same-module entity; else skip;
  - anything else (literal, attribute, cross-module call, comprehension …) → skip.
**Known limitation (it can both under- AND over-fire on reassignment):** the read is the
name's FINAL taint, not its taint at the sink line. A name reassigned raw→trusted before
the sink under-fires (a benign FN); a name reassigned trusted→raw *after* an earlier
sink over-fires that earlier sink (a real FP). Both are bounded to multi-assignment
shapes; the honest fix is flow-sensitive call-site taint in the engine (a follow-up). The
labeled corpus tracks the realized FP rate; this is documented, not hidden.
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
    "call_site_var_taints",
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
    """Yield every ``ast.Call`` in *node*'s own scope (never descending into nested
    def/class/lambda — those are separate scopes / separate entities)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Lambda):
            for default in (*child.args.defaults, *child.args.kw_defaults):
                if default is not None:
                    if isinstance(default, ast.Call):
                        yield default
                    yield from _own_calls(default)
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


def _arg_taint(
    arg: ast.expr, module: str, var_taints: Mapping[str, TaintState], context: AnalysisContext, qualname: str
) -> TaintState | None:
    if isinstance(arg, ast.Starred):
        arg = arg.value
    if isinstance(arg, ast.Name):
        return var_taints.get(arg.id)  # None when the name is not a tracked var → skip
    if isinstance(arg, ast.Call):
        if (
            isinstance(arg.func, ast.Attribute)
            and isinstance(arg.func.value, ast.Name)
            and arg.func.value.id in {"self", "cls"}
        ):
            caller_entity = context.entities.get(qualname)
            if caller_entity is not None and caller_entity.kind == "method":
                enclosing_class = qualname.rsplit(".", 1)[0]
                candidate = f"{enclosing_class}.{arg.func.attr}"
                return context.project_return_taints.get(candidate)
        callee = dotted_name(arg.func)
        if callee is not None and "." not in callee and module:
            return context.project_return_taints.get(f"{module}.{callee}")
        return None
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in ("self", "cls"):
        # ``self.<attr>``/``cls.<attr>`` resolves against the cross-method class
        # attribute summary (closure A): the enclosing class is the qualname minus
        # the method leaf. None when the attribute has no summarised write.
        enclosing_class = qualname.rsplit(".", 1)[0] if "." in qualname else ""
        return context.class_attr_taints.get(enclosing_class, {}).get(arg.attr)
    return None


def worst_arg_taint(
    call: ast.Call, qualname: str, context: AnalysisContext, var_taints: Mapping[str, TaintState]
) -> TaintState | None:
    """The LEAST-trusted (highest TRUST_RANK) resolvable argument taint of *call*, or
    None when no argument resolves. Positional + keyword args are considered.

    ``var_taints`` is the per-variable taint map to resolve ``ast.Name`` args against
    — pass the FLOW-SENSITIVE snapshot for *call*'s enclosing statement (see
    :func:`call_site_var_taints`) so a name reassigned after the call is read at its
    taint AT the call line, not the final map."""
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


def _calls_with_enclosing_stmt(
    node: ast.AST, cur_stmt: ast.stmt | None = None
) -> Iterator[tuple[ast.Call, ast.stmt | None]]:
    """Yield ``(call, nearest_enclosing_stmt)`` for every own-scope call (never
    descending into nested def/class/lambda — separate scopes). The enclosing
    statement is the deepest ``ast.stmt`` ancestor; ``None`` only for the
    degenerate case of a call directly under the function node with no statement
    between (not reachable for a real body)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        new_stmt = child if isinstance(child, ast.stmt) else cur_stmt
        if isinstance(child, ast.Call):
            yield child, new_stmt
        yield from _calls_with_enclosing_stmt(child, new_stmt)


def call_site_var_taints(
    func_node: ast.AST, qualname: str, context: AnalysisContext
) -> dict[int, Mapping[str, TaintState]]:
    """Map ``id(call) -> the var-taint snapshot to resolve that call's args against``.

    Flow-sensitive: each own-scope call maps to its enclosing statement's snapshot
    (``function_call_site_taints`` — the taint AT that statement). Falls back to the
    function's final ``function_var_taints`` when no snapshot exists (older contexts,
    or an L2-skipped function), preserving the previous flow-insensitive behavior."""
    snapshots = context.function_call_site_taints.get(qualname, {})
    final = context.function_var_taints.get(qualname, {})
    result: dict[int, Mapping[str, TaintState]] = {}
    for call, stmt in _calls_with_enclosing_stmt(func_node):
        snap = snapshots.get(id(stmt)) if stmt is not None else None
        result[id(call)] = snap if snap is not None else final
    return result


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
            site_taints = call_site_var_taints(entity.node, qualname, context)
            final = context.function_var_taints.get(qualname, {})
            module = _module_for_qualname(lookup_name, context)
            alias_map = context.alias_maps.get(module, {}) if module is not None else {}
            for call, dotted in sink_calls(entity.node, self.SINKS, alias_map, module or ""):
                if not self._accept_call(call):
                    continue
                worst = worst_arg_taint(call, qualname, context, site_taints.get(id(call), final))
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
