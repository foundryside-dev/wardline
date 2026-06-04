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
import hashlib
from typing import TYPE_CHECKING

from wardline.core.registry import REGISTRY, REGISTRY_VERSION
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.taint.provider import FunctionTaint, SeedResult

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.index import Entity
    from wardline.scanner.taint.provider import SeedContext

_VOCAB_PREFIX = "wardline.decorators"
_LOOM_MARKERS_PREFIX = "loom_markers"
_TAINTSTATE_FQN = "wardline.core.taints.TaintState"


def vocabulary_star_exports() -> dict[str, dict[str, str]]:
    """Statically-known star-export map for builtin trust-marker modules.

    ``from wardline.decorators import *`` and ``from loom_markers import *`` bring
    the :data:`REGISTRY` decorator names into the importing module's namespace.
    Wardline knows these names a priori (they are the REGISTRY keys), so it can
    materialise them WITHOUT importing or executing the target module — the
    static-analyzer boundary is preserved. Returned as
    ``{source_module_fqn: {local_name: target_fqn}}`` for
    :func:`wardline.scanner.ast_primitives.build_import_alias_map`. Only these
    builtin marker modules resolve; every other star import stays unresolved and
    surfaces as an honest ``WLN-ENGINE-UNKNOWN-IMPORT`` FACT (fail-closed
    preserved).
    """
    return {
        _VOCAB_PREFIX: {name: f"{_VOCAB_PREFIX}.{name}" for name in REGISTRY},
        _LOOM_MARKERS_PREFIX: {name: f"{_LOOM_MARKERS_PREFIX}.{name}" for name in REGISTRY},
    }


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


def _seed_identity(seed: object) -> str:
    """A stable identity string for a boundary type's seed callable.

    For a Python function/lambda, keys on the bytecode + constants
    (``__code__.co_code`` + ``co_consts``) — so two DISTINCT lambda bodies that share
    ``__qualname__ == "<lambda>"`` get DISTINCT identities (closing the cache
    cross-contamination false-green: two grammars differing only in a lambda seed
    body must not share cached summaries). For a non-function callable (no
    ``__code__``), falls back to ``__qualname__`` / ``repr``. This only ever
    OVER-invalidates the summary cache (a changed seed body → a different identity →
    a cold re-scan), never wrongly reuses — strictly safe."""
    code = getattr(seed, "__code__", None)
    if code is not None:
        return f"{code.co_code.hex()}|{code.co_consts!r}"
    return str(getattr(seed, "__qualname__", repr(seed)))


def _grammar_digest(boundary_types: tuple[BoundaryType, ...]) -> str:
    """A stable digest over a grammar's boundary types — its declaration identity.

    Bound into the provider fingerprint so two DIFFERENT loaded grammars cannot
    share cached module summaries (a false-green correctness bug — design spec §6).
    Order-sensitive over (name, prefix, group, seed identity, level-arg schema).
    """
    h = hashlib.sha256()
    for bt in boundary_types:
        parts = [bt.canonical_name, bt.module_prefix, str(bt.group), _seed_identity(bt.seed)]
        for la in bt.level_args:
            allowed = ",".join(sorted(t.value for t in la.allowed))
            default = la.default.value if la.default is not None else ""
            parts.append(f"{la.arg_name}:{allowed}:{default}")
        h.update(("\x00".join(parts) + "\x01").encode("utf-8"))
    return h.hexdigest()[:16]


class DecoratorTaintSourceProvider:
    """Seeds taints from a trust grammar's boundary types (Track 2).

    ``boundary_types`` defaults to the builtin vocabulary, so existing
    constructions (``DecoratorTaintSourceProvider()``) are behavior-identical. An
    extended grammar (builtins + agent-defined types) makes the provider recognize
    custom markers via the same generic loop the builtins ride."""

    def __init__(self, *, boundary_types: tuple[BoundaryType, ...] | None = None) -> None:
        self._boundary_types: tuple[BoundaryType, ...] = (
            boundary_types if boundary_types is not None else BUILTIN_BOUNDARY_TYPES
        )

    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult:
        candidates: list[FunctionTaint] = []
        unprovable: list[str] = []
        for deco in entity.node.decorator_list:
            ft, unprov = self._match(deco, ctx.alias_map)
            if ft is not None:
                candidates.append(ft)
            elif unprov is not None:
                unprovable.append(unprov)
        if not candidates:
            # No proven seed. Any matched-but-unreadable CUSTOM boundaries are surfaced
            # (T2.4) and the L1 fallback seeds UNKNOWN_RAW (source="default", not
            # anchored — there is no usable declaration). Builtins never set ``unprov``.
            return SeedResult(taint=None, unprovable_boundaries=tuple(unprovable))
        # A proven seed exists. If an unprovable CUSTOM boundary ALSO matched, it must
        # not be silently over-trusted by the provable one (a false-green): add an
        # UNKNOWN_RAW contribution so the least-trusted-per-field meet below drags the
        # seed to the fail-closed value, AND report the unprovable names (a FACT fires).
        # This is consistent with the multi-decorator conflict rule: contradictory
        # annotations take the weakest, and an unreadable annotation is the weakest of
        # all. (Builtins never reach here with an unprovable, so the oracle is unmoved.)
        if unprovable:
            candidates.append(FunctionTaint(TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_RAW))
        # Multiple trust decorators on one function is an authoring conflict; take the
        # LEAST-trusted value PER FIELD independently (highest TRUST_RANK). Order-
        # independent (the per-field max does not depend on candidate order).
        body = max((ft.body_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        ret = max((ft.return_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        return SeedResult(taint=FunctionTaint(body, ret), unprovable_boundaries=tuple(unprovable))

    def fingerprint(self) -> str:
        # Builtin-only grammar keeps TODAY's EXACT string (cache/baseline stability —
        # design spec §6). A custom grammar appends a stable digest so cached
        # summaries from a different loaded grammar cannot cross-contaminate.
        if self._boundary_types == BUILTIN_BOUNDARY_TYPES:
            return f"decorator-vocab:{REGISTRY_VERSION}"
        return f"decorator-vocab:{REGISTRY_VERSION}+grammar:{_grammar_digest(self._boundary_types)}"

    def _match(self, deco: ast.expr, alias_map: Mapping[str, str]) -> tuple[FunctionTaint | None, str | None]:
        """Match one decorator against the loaded boundary types. Returns:

        ``(seed, None)``   — a boundary type matched and its levels proved;
        ``(None, name)``   — a CUSTOM type matched but a required level was unreadable
                             (fail-closed; surfaced as a FACT). Builtins return
                             ``(None, None)`` here to stay silent (oracle-preserving);
        ``(None, None)``   — no boundary type matched (not vocabulary — 'no opinion').
        """
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None:
            return None, None
        # A decorator matches a boundary type when its FQN is UNDER the type's module
        # prefix and its final segment is the canonical name. This accepts BOTH the
        # package re-export (``wardline.decorators.trusted``) and the submodule path
        # (``wardline.decorators.trust.trusted``) — preserving the pre-Track-2 matcher
        # exactly (it used the same prefix + last-segment rule), and generalizing it
        # consistently for custom types.
        last = fqn.rsplit(".", 1)[-1]
        for bt in self._boundary_types:
            if last != bt.canonical_name or not fqn.startswith(bt.module_prefix + "."):
                continue
            levels: dict[str, TaintState] = {}
            unreadable = False
            for la in bt.level_args:
                lvl = _read_level(deco, la.arg_name, allowed=la.allowed, default=la.default, alias_map=alias_map)
                if lvl is None:
                    unreadable = True
                    break
                levels[la.arg_name] = lvl
            if unreadable:
                return None, (None if bt.builtin else bt.canonical_name)
            return bt.seed(levels), None
        return None, None
