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
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.taint.provider import FunctionTaint, SeedResult

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.index import Entity
    from wardline.scanner.taint.provider import SeedContext

_VOCAB_PREFIX = "wardline.decorators"
_WEFT_MARKERS_PREFIX = "weft_markers"
_TAINTSTATE_FQN = "wardline.core.taints.TaintState"

# The top-level import roots of every BUILTIN marker module — derived dynamically
# from the grammar so adding a builtin marker root (e.g. a future ``weft_markers``
# sibling) automatically participates in shadow fail-closed + exact-export matching.
# A ``weft_markers`` boundary type has module_prefix ``weft_markers`` (root
# ``weft_markers``); a ``wardline.decorators`` one has root ``wardline``.
_BUILTIN_MARKER_ROOTS: frozenset[str] = frozenset(
    bt.module_prefix.split(".")[0] for bt in BUILTIN_BOUNDARY_TYPES if getattr(bt, "builtin", False)
)


def vocabulary_star_exports() -> dict[str, dict[str, str]]:
    """Statically-known star-export map for builtin trust-marker modules.

    ``from wardline.decorators import *`` and ``from weft_markers import *`` bring
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
        _WEFT_MARKERS_PREFIX: {name: f"{_WEFT_MARKERS_PREFIX}.{name}" for name in REGISTRY},
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


def _shadowed_builtin_roots(project_modules: frozenset[str]) -> frozenset[str]:
    """Return the builtin marker roots the scanned project SHADOWS.

    Builtin marker declarations must refer to the installed marker package, not a
    module supplied by the scanned project. A root is shadowed when the project
    itself defines a TOP-LEVEL module/package equal to that root (e.g. its own
    ``wardline`` or ``weft_markers`` package): Python import resolution can then
    bind ``wardline.decorators`` / ``weft_markers`` to attacker-controlled code, so
    builtin matching fails closed for markers under that root.

    Only the FIRST dotted component is compared, so an unrelated nested module such
    as ``app.wardline_helper`` or ``myweft.wardline`` does NOT trip a shadow.
    """
    project_roots = {module.split(".", 1)[0] for module in project_modules}
    return frozenset(project_roots & _BUILTIN_MARKER_ROOTS)


def _is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool:
    """Return whether *fqn* is one of the exact builtin decorator exports.

    For a builtin boundary type with prefix ``P``, only the public re-export
    ``P.<name>`` and the implementation-module export ``P.trust.<name>`` are
    accepted (mirroring ``wardline/decorators/__init__.py`` and
    ``wardline/decorators/trust.py``). Prefix + arbitrary-nested + final-segment
    paths (e.g. ``wardline.decorators.evil.trusted``) are rejected for builtins.
    """
    return fqn in {
        f"{module_prefix}.{canonical_name}",
        f"{module_prefix}.trust.{canonical_name}",
    }


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
    ignored_args: frozenset[str] = frozenset(),
) -> TaintState | None:
    """Read a level keyword arg from a decorator, normalised + allow-checked.

    Returns ``default`` when the decorator is not called or the arg is absent;
    ``None`` (fail-closed) when the arg is present but unreadable, an invalid
    state, outside ``allowed``, duplicated, or mixed with malformed decorator
    call syntax. The real level-bearing decorators are keyword-only; positional
    args and unexpected keywords are not trusted as the default level.
    """
    if not isinstance(deco, ast.Call):
        return default
    if deco.args:
        return None
    values: list[ast.expr] = []
    for kw in deco.keywords:
        if kw.arg is None:
            if not isinstance(kw.value, ast.Dict):
                return None
            for key, value in zip(kw.value.keys, kw.value.values, strict=True):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    return None
                if key.value in ignored_args:
                    continue
                if key.value != arg:
                    return None
                values.append(value)
            continue
        if kw.arg == arg:
            values.append(kw.value)
            continue
        if kw.arg in ignored_args:
            continue
        return None
    if not values:
        return default
    if len(values) != 1:
        return None
    token = _level_token(values[0], alias_map)
    if token is None:
        return None
    try:
        level = TaintState(token)
    except ValueError:
        return None
    return level if level in allowed else None


def _seed_value_identity(value: object) -> str:
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    if isinstance(value, TaintState):
        return f"TaintState:{value.value}"
    if isinstance(value, FunctionTaint):
        return (
            "FunctionTaint("
            f"body={_seed_value_identity(value.body_taint)},"
            f"return={_seed_value_identity(value.return_taint)}"
            ")"
        )
    if isinstance(value, (tuple, list)):
        return type(value).__name__ + "(" + ",".join(_seed_value_identity(v) for v in value) + ")"
    if isinstance(value, dict):
        parts = sorted((_seed_value_identity(k), _seed_value_identity(v)) for k, v in value.items())
        return "dict(" + ",".join(f"{k}:{v}" for k, v in parts) + ")"

    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if isinstance(module, str) and isinstance(qualname, str):
        return f"{module}.{qualname}"
    name = getattr(value, "__name__", None)
    if isinstance(module, str) and isinstance(name, str):
        return f"{module}.{name}"
    return repr(value)


def _closure_identity(seed: object) -> tuple[str, ...]:
    items: list[str] = []
    for cell in getattr(seed, "__closure__", None) or ():
        try:
            items.append(_seed_value_identity(cell.cell_contents))
        except ValueError:
            items.append("<empty-cell>")
    return tuple(items)


def _seed_identity(seed: object) -> str:
    """A stable identity string for a boundary type's seed callable.

    For a Python function/lambda, keys on bytecode, constants, referenced names,
    defaults, closures, and the stable identities of referenced globals. Bytecode
    alone is not enough: ``return SAFE_SEED`` and ``return RAW_SEED`` can share
    ``co_code``/``co_consts`` while differing only by ``co_names`` or the value bound
    to that name. For a non-function callable (no ``__code__``), falls back to
    ``__qualname__`` / ``repr``. This only ever OVER-invalidates the summary cache (a
    changed seed body/dependency → a different identity → a cold re-scan), never
    wrongly reuses — strictly safe."""
    code = getattr(seed, "__code__", None)
    if code is not None:
        globals_map = getattr(seed, "__globals__", {})
        global_parts = []
        if isinstance(globals_map, dict):
            for name in code.co_names:
                global_parts.append(f"{name}={_seed_value_identity(globals_map.get(name, '<missing-global>'))}")
        return "|".join(
            (
                str(getattr(seed, "__module__", "")),
                str(getattr(seed, "__qualname__", getattr(seed, "__name__", ""))),
                code.co_code.hex(),
                repr(code.co_consts),
                repr(code.co_names),
                repr(code.co_freevars),
                repr(code.co_cellvars),
                repr(getattr(seed, "__defaults__", None)),
                _seed_value_identity(getattr(seed, "__kwdefaults__", None)),
                repr(_closure_identity(seed)),
                repr(tuple(global_parts)),
            )
        )
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
        shadowed_roots = _shadowed_builtin_roots(ctx.project_modules)
        for deco in entity.node.decorator_list:
            ft, unprov = self._match(deco, ctx.alias_map, shadowed_roots)
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

    def fingerprint_for_project(self, project_modules: frozenset[str]) -> str:
        """Fingerprint declaration inputs that are external to a single module.

        Builtin seeding depends on WHICH builtin marker roots the scanned project
        shadows; bind the EXACT shadowed-root SET into the summary-cache key so a
        warm cache cannot reuse a TRUSTED summary across scans with different
        shadow states (cross-root cache poisoning). Crucially this is per-root: a
        scan that shadows only ``wardline`` and one that shadows only
        ``weft_markers`` must NOT collide on the cache key. When nothing is
        shadowed (the common case), returns the bare :meth:`fingerprint` string,
        preserving today's exact cache/baseline-stable value.
        """
        shadowed = _shadowed_builtin_roots(project_modules)
        base = self.fingerprint()
        if not shadowed:
            return base
        return f"{base}:shadowed-roots={','.join(sorted(shadowed))}"

    def _match(
        self,
        deco: ast.expr,
        alias_map: Mapping[str, str],
        shadowed_roots: frozenset[str],
    ) -> tuple[FunctionTaint | None, str | None]:
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
        # Builtin markers are security-sensitive defaults: a scanned project could
        # ship its own ``wardline/decorators`` (or ``weft_markers``) no-op shadowing
        # the real package, spoof @trusted, and suppress real taint→sink flows (a
        # false GREEN). So a builtin matches ONLY an EXACT known export
        # (``P.<name>`` or ``P.trust.<name>``), and is rejected entirely when its
        # marker ROOT is shadowed by a project-local top-level module. Custom
        # (non-builtin) grammar markers keep the documented prefix + canonical-name
        # rule — a project defining its OWN custom marker package is the intended
        # extension use, and its root is not a builtin we ship.
        last = fqn.rsplit(".", 1)[-1]
        for bt in self._boundary_types:
            if bt.builtin:
                root = bt.module_prefix.split(".")[0]
                if root in shadowed_roots or not _is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
                    continue
            elif last != bt.canonical_name or not fqn.startswith(bt.module_prefix + "."):
                continue
            levels: dict[str, TaintState] = {}
            unreadable = False
            for la in bt.level_args:
                # Legacy review fixtures and older sample code sometimes supplied
                # ``to_level`` on ``@trusted``. Treat it as inert compatibility
                # only when the real ``level`` argument remains statically readable;
                # genuinely unknown kwargs still fail closed.
                ignored = frozenset({"to_level"}) if bt.canonical_name == "trusted" else frozenset()
                lvl = _read_level(
                    deco,
                    la.arg_name,
                    allowed=la.allowed,
                    default=la.default,
                    alias_map=alias_map,
                    ignored_args=ignored,
                )
                if lvl is None:
                    unreadable = True
                    break
                levels[la.arg_name] = lvl
            if unreadable:
                return None, (None if bt.builtin else bt.canonical_name)
            return bt.seed(levels), None
        return None, None
