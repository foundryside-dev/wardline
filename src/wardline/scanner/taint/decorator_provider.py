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
import json
import re
import sys
from types import CodeType, ModuleType
from typing import TYPE_CHECKING

from wardline.core.registry import REGISTRY, REGISTRY_VERSION
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.marker_reader import VOCAB_PREFIX as _VOCAB_PREFIX
from wardline.scanner.marker_reader import WEFT_MARKERS_PREFIX as _WEFT_MARKERS_PREFIX
from wardline.scanner.marker_reader import LevelVerdict, ModuleCensus, call_shape_offences, unknown_vocabulary_marker
from wardline.scanner.marker_reader import is_builtin_decorator_fqn as _is_builtin_decorator_fqn
from wardline.scanner.marker_reader import read_level as _read_level
from wardline.scanner.marker_reader import resolve_decorator_fqn as _resolve_decorator_fqn
from wardline.scanner.marker_reader import shadowed_builtin_roots as _shadowed_builtin_roots
from wardline.scanner.taint.provider import FunctionTaint, SeedResult

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from wardline.scanner.index import Entity
    from wardline.scanner.taint.provider import SeedContext


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


# --- Grammar digest (P8) -----------------------------------------------------
#
# The digest is a full SHA-256 over CANONICAL JSON. Delimiter-joined preimages are
# forbidden here and the reason is concrete: any join over free-form text is
# ambiguous, so ``("a<D>b", "c")`` and ``("a", "b<D>c")`` hash identically for the
# separator ``<D>`` and two DIFFERENT grammars share a cache key. Structured JSON
# closes that — every field is its own delimited-by-construction slot, and JSON
# escapes any separator byte that appears inside a value. No truncation either: a
# 16-hex prefix is a 64-bit birthday surface on a value that gates cache reuse.

# Recursion guard for pathological / self-referential values reachable through a
# seed's globals or defaults. Set far above anything a real trust grammar reaches
# (measured maximum on this tree: 7 for a pack whose seed calls a module-level
# helper that touches wardline's own classes), so a capped record is never mistaken
# for discrimination — if either guard trips, the digest UNDER-discriminates and the
# guard must rise rather than the record be accepted.
_MAX_VALUE_DEPTH = 64
# Ceiling on how many distinct objects one digest may structurally expand. Two
# orders of magnitude above the measured worst case (180 objects, <1 ms) — a safety
# valve against a seed that reaches a pathological object graph, never a routine cap.
_MAX_EXPANDED_NODES = 20_000


class _Walk:
    """Traversal state for one ``_grammar_digest`` call.

    A referenced global may reference back (``seed`` → ``_helper`` → ``seed``) and one
    object may be reachable by many paths, so the walk needs both cycle detection and
    memoization: ``active`` breaks cycles, ``memo`` makes the cost linear in the number
    of DISTINCT reachable objects rather than exponential in the paths to them.
    ``alive`` pins every memoized object for the duration so CPython cannot recycle an
    ``id()`` underneath the memo.
    """

    __slots__ = ("active", "alive", "budget", "memo")

    def __init__(self) -> None:
        self.memo: dict[int, dict[str, object]] = {}
        self.alive: list[object] = []
        self.active: set[int] = set()
        self.budget: int = _MAX_EXPANDED_NODES


def _canonical_json(value: object) -> str:
    """Compact, key-sorted, ASCII-escaped JSON — the one canonical encoding."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _named(value: object) -> dict[str, object]:
    """The (module, qualname) pair for an object, as distinct slots — never joined."""
    return {
        "module": str(getattr(value, "__module__", "") or ""),
        "qualname": str(getattr(value, "__qualname__", None) or getattr(value, "__name__", "") or ""),
    }


def _expanded(value: object, walk: _Walk, depth: int, build: Callable[[int], dict[str, object]]) -> dict[str, object]:
    """Memoized, cycle-safe, budgeted structural expansion of one object."""
    key = id(value)
    cached = walk.memo.get(key)
    if cached is not None:
        return cached
    if key in walk.active:
        # A reference cycle. The back-edge carries the NAME only; the object's own
        # structure is already being expanded higher up this same path, so the
        # structure is in the preimage exactly once and a body change still moves it.
        return {"t": "cycle", **_named(value)}
    if walk.budget <= 0:
        return {"t": "budget-exhausted", **_named(value)}
    walk.budget -= 1
    walk.active.add(key)
    try:
        record = build(depth)
    finally:
        walk.active.discard(key)
    walk.alive.append(value)
    walk.memo[key] = record
    return record


def _has_code(value: object) -> bool:
    return getattr(value, "__code__", None) is not None


# Top-level packages whose bodies are NOT part of a pack's declaration identity and
# are therefore keyed by name, not structure:
#
#  * the standard library and builtins — these change only with the interpreter, which
#    is not the grammar, and walking them is what made the digest process-UNSTABLE
#    (measured: ``object.__new__`` and ``dataclasses.Field``'s ``_MISSING_TYPE``
#    sentinels both repr with a memory address, so every custom grammar got a fresh
#    digest every run — the exact cold-cache symptom this task removed elsewhere);
#  * ``wardline`` itself — already versioned into the SAME summary-cache key by
#    ``_RESOLVER_VERSION``, ``REGISTRY_VERSION`` and the summary schema version, so
#    re-keying it here buys nothing and costs a 2.9 MiB preimage.
#
# Everything else — the pack's own modules AND any third-party helper library it
# imports — is expanded structurally.
_OPAQUE_PACKAGES = frozenset({"builtins", "wardline"}) | frozenset(sys.stdlib_module_names)

# CPython's default ``object.__repr__`` idiom. A memory address is process noise, never
# durable information about a value, so it is normalised out of the last-resort arm;
# matching " at 0x…" rather than bare "0x…" keeps genuine hex literals in a repr
# (``Mask(bits=0xFF)``) discriminating.
_ADDRESS_RE = re.compile(r" at 0x[0-9a-fA-F]+")


def _is_structurally_opaque(value: object) -> bool:
    """True when an object's BODY is out of scope for a grammar's identity.

    The fence names the packages whose bodies are versioned SOMEWHERE ELSE. An absent
    or empty ``__module__`` names nothing, so it is NOT opaque: an unknown module is
    not a versioned-elsewhere module, and defaulting it to "keyed by name" would fail
    OPEN — precisely the hole this pass exists to close. A function ``exec``-ed into a
    namespace with no ``__name__`` (the shape a dynamically built grammar takes) has
    ``__module__ is None`` and must still be expanded.
    """
    module = getattr(value, "__module__", None)
    if not isinstance(module, str) or not module:
        return False
    return module.split(".", 1)[0] in _OPAQUE_PACKAGES


def _seed_value_identity(value: object, walk: _Walk | None = None, _depth: int = 0) -> dict[str, object]:
    """A JSON-serializable, type-TAGGED identity record for one Python value.

    Every record carries its type tag ``t``, so ``"1"`` (a str) and ``1`` (an int)
    can never produce the same record, and no value's encoding can be confused with
    another's by concatenation.
    """
    if walk is None:
        walk = _Walk()
    if _depth > _MAX_VALUE_DEPTH:
        return {"t": "depth-capped"}
    d = _depth + 1
    if value is None:
        return {"t": "none"}
    if value is Ellipsis:
        return {"t": "ellipsis"}
    if value is NotImplemented:
        return {"t": "notimplemented"}
    # TaintState is a StrEnum and bool is an int, so both MUST be tested before their
    # supertypes or they collapse into the str/int arms.
    if isinstance(value, TaintState):
        return {"t": "taint", "v": value.value}
    if isinstance(value, FunctionTaint):
        return {
            "t": "function_taint",
            "body": _seed_value_identity(value.body_taint, walk, d),
            "return": _seed_value_identity(value.return_taint, walk, d),
        }
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": str(value)}
    if isinstance(value, float):
        return {"t": "float", "v": repr(value)}
    if isinstance(value, complex):
        return {"t": "complex", "v": repr(value)}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (bytes, bytearray)):
        return {"t": "bytes", "v": bytes(value).hex()}
    if isinstance(value, CodeType):
        # Nested code (an inner def/lambda/comprehension lands in ``co_consts``)
        # recurses into the SAME structural normalization. ``repr(code)`` is not an
        # accepted canonical form: it embeds the object's memory ADDRESS and its
        # source filename/first line, so it is simultaneously unstable across
        # processes and sensitive to pure layout.
        return {"t": "code", "v": _code_identity(value, walk, d)}
    if isinstance(value, ModuleType):
        return {"t": "module", "v": str(getattr(value, "__name__", ""))}
    if isinstance(value, (tuple, list)):
        return {"t": type(value).__name__, "v": [_seed_value_identity(v, walk, d) for v in value]}
    if isinstance(value, (frozenset, set)):
        items = [_seed_value_identity(v, walk, d) for v in value]
        items.sort(key=_canonical_json)
        return {"t": type(value).__name__, "v": items}
    if isinstance(value, dict):
        pairs = [[_seed_value_identity(k, walk, d), _seed_value_identity(v, walk, d)] for k, v in value.items()]
        pairs.sort(key=_canonical_json)
        return {"t": "dict", "v": pairs}

    # --- Structural arms: a referenced FUNCTION or CLASS is keyed by its BODY --------
    #
    # Keying a referenced global by ``module.qualname`` alone is a measured cache-
    # poisoning hole, and it is the LIVE path: a production pack loads as a real
    # importable module, so `def seed(levels): return _helper(levels)` is the ordinary
    # shape. Under a name-only key, editing `_helper` to return ASSURED instead of
    # EXTERNAL_RAW leaves the digest byte-identical and a warm cache answers the new
    # grammar with the old grammar's verdicts. The body has to be in the preimage.
    if _has_code(value) and not _is_structurally_opaque(value):
        return _expanded(value, walk, d, lambda dd: _function_identity(value, walk, dd))
    if isinstance(value, type) and not _is_structurally_opaque(value):
        return _expanded(value, walk, d, lambda dd: _class_identity(value, walk, dd))
    # staticmethod / classmethod / bound method wrappers around a real function.
    inner = getattr(value, "__func__", None)
    if inner is not None and _has_code(inner):
        return {"t": "wrapped_function", "wrapper": type(value).__name__, "v": _seed_value_identity(inner, walk, d)}
    if isinstance(value, property):
        return {
            "t": "property",
            "fget": _seed_value_identity(value.fget, walk, d),
            "fset": _seed_value_identity(value.fset, walk, d),
            "fdel": _seed_value_identity(value.fdel, walk, d),
        }

    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if isinstance(module, str) and isinstance(qualname, str):
        return {"t": "ref", "module": module, "qualname": qualname}
    name = getattr(value, "__name__", None)
    if isinstance(module, str) and isinstance(name, str):
        return {"t": "ref", "module": module, "name": name}
    # LAST RESORT, and the one arm that can admit a memory address into the preimage
    # (``<Foo object at 0x…>``). That over-invalidates — a cold cache every process for
    # a grammar that reaches such an object — which is the SAFE direction. Normalising
    # the address away would instead make two differently-CONFIGURED instances of one
    # class collide, which is the false green this digest exists to prevent.
    return {"t": "repr", "v": _ADDRESS_RE.sub(" at 0x<addr>", repr(value))}


def _function_identity(fn: object, walk: _Walk, depth: int) -> dict[str, object]:
    """Structural record for a function: its code, its bindings, and its globals."""
    code = fn.__code__  # type: ignore[attr-defined]
    globals_map = getattr(fn, "__globals__", None)
    globals_record: dict[str, object] = {}
    if isinstance(globals_map, dict):
        for name in code.co_names:
            globals_record[name] = (
                _seed_value_identity(globals_map[name], walk, depth) if name in globals_map else {"t": "missing-global"}
            )
    return {
        "kind": "function",
        **_named(fn),
        "code": _code_identity(code, walk, depth),
        "defaults": _seed_value_identity(getattr(fn, "__defaults__", None), walk, depth),
        "kwdefaults": _seed_value_identity(getattr(fn, "__kwdefaults__", None), walk, depth),
        "closure": _closure_identity(fn, walk, depth),
        "globals": globals_record,
    }


def _class_identity(cls: type, walk: _Walk, depth: int) -> dict[str, object]:
    """Structural record for a class: its own namespace, plus its bases.

    ``vars(cls)`` carries the method bodies (each expanded through the function arm
    above) AND the class-level data a seed's behaviour can turn on. ``__bases__`` is
    walked so a change to an INHERITED method also moves the digest — ``vars`` is
    own-dict only.

    ``__firstlineno__`` is dropped: since 3.13 CPython stores the class's source line
    in its namespace, and it is exactly the layout noise ``_code_identity`` excludes —
    left in, moving a class down a file would cold-invalidate every warm cache.
    """
    members = {str(k): _seed_value_identity(v, walk, depth) for k, v in vars(cls).items() if k != "__firstlineno__"}
    return {
        "kind": "class",
        **_named(cls),
        "members": members,
        "bases": [_seed_value_identity(b, walk, depth) for b in getattr(cls, "__bases__", ())],
    }


def _code_identity(code: CodeType, walk: _Walk | None = None, _depth: int = 0) -> dict[str, object]:
    """Structural normalization of a code object — behaviour in, layout out.

    IN: bytecode, constants (recursively, including nested code objects), referenced
    names, argument/local/free/cell variable names, arity and flags.
    Also IN: ``co_exceptiontable``. Since 3.11 the ``try``/``except`` handler ranges
    live there and are NOT a pure function of ``co_code``, so a change confined to
    exception-handler extents would otherwise be invisible.
    OUT: ``co_filename``, ``co_firstlineno``, ``co_linetable``, ``co_positions`` and
    ``co_stacksize`` — the first four are pure source-layout noise (re-indenting or
    adding a comment must not cold-invalidate every warm cache) and the fifth is a
    function of the bytecode that is already keyed.
    """
    if walk is None:
        walk = _Walk()
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "flags": code.co_flags,
        "name": code.co_name,
        "qualname": getattr(code, "co_qualname", code.co_name),
        "bytecode": code.co_code.hex(),
        "exceptiontable": bytes(getattr(code, "co_exceptiontable", b"")).hex(),
        "consts": [_seed_value_identity(c, walk, _depth + 1) for c in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
    }


def _closure_identity(seed: object, walk: _Walk | None = None, _depth: int = 0) -> list[dict[str, object]]:
    """Identity records for a seed's closure CELL CONTENTS, in ``co_freevars`` order.

    Two seeds built by the same factory share bytecode, ``co_freevars`` and
    everything else structural — only the captured VALUES differ, so the cell
    contents are the sole discriminator.
    """
    if walk is None:
        walk = _Walk()
    items: list[dict[str, object]] = []
    for cell in getattr(seed, "__closure__", None) or ():
        try:
            items.append(_seed_value_identity(cell.cell_contents, walk, _depth))
        except ValueError:
            items.append({"t": "empty-cell"})
    return items


def _seed_identity(seed: object, walk: _Walk | None = None) -> dict[str, object]:
    """A JSON-structured identity record for a boundary type's seed callable.

    For a Python function/lambda, keys on module and qualname as DISTINCT fields
    (never joined — ``("x|y", "z")`` and ``("x", "y|z")`` must not collide), plus the
    normalized code structure, defaults, closure cell contents, and the identities of
    referenced globals. Bytecode alone is not enough: ``return SAFE_SEED`` and
    ``return RAW_SEED`` can share ``co_code``/``co_consts`` while differing only by
    ``co_names`` or the value bound to that name — and a referenced global that is
    itself a function or class is keyed by its BODY, not its name, so editing a
    module-level helper the seed calls moves the digest.

    For a non-function callable (no ``__code__``) this DELIBERATELY falls back to
    ``repr``, which for a plain instance embeds its memory address. Keying on the
    class instead would make two differently-CONFIGURED instances of one callable
    class collide — under-discrimination, i.e. the cross-grammar cache reuse this
    digest exists to prevent. Over-invalidating (a changed seed → a different
    identity → a cold re-scan) is strictly safe; under-invalidating is a false green.
    """
    if walk is None:
        walk = _Walk()
    if not _has_code(seed):
        return {
            "kind": "opaque",
            "qualname": str(getattr(seed, "__qualname__", "")),
            "repr": repr(seed),
        }
    return _function_identity(seed, walk, 0)


def _grammar_digest(boundary_types: tuple[BoundaryType, ...]) -> str:
    """A stable digest over a grammar's boundary types — its declaration identity.

    Bound into the provider fingerprint so two DIFFERENT loaded grammars cannot
    share cached module summaries (a false-green correctness bug — design spec §6).
    Order-sensitive over the full declaration surface: canonical name, module prefix,
    group, the ``builtin`` flag, the ORDERED level-argument schema, and structural
    seed identity. Returns 64 lowercase hex characters — a full, untruncated SHA-256
    over compact key-sorted canonical JSON.
    """
    # ONE walk for the whole grammar: a helper shared by two boundary types is
    # expanded once and both records carry that same expansion, so the cost stays
    # linear in distinct reachable objects while every body change still moves it.
    walk = _Walk()
    records = [
        {
            "canonical_name": bt.canonical_name,
            "module_prefix": bt.module_prefix,
            "group": bt.group,
            "builtin": bool(bt.builtin),
            "level_args": [
                {
                    "arg_name": la.arg_name,
                    # A set has no order; sorting the VALUES is what makes the record
                    # canonical without smuggling iteration order into the digest.
                    "allowed": sorted(t.value for t in la.allowed),
                    # JSON ``null`` for "required", never the empty string — the empty
                    # string is a value a level name could in principle take.
                    "default": (la.default.value if la.default is not None else None),
                }
                for la in bt.level_args
            ],
            "seed": _seed_identity(bt.seed, walk),
        }
        for bt in boundary_types
    ]
    return hashlib.sha256(_canonical_json(records).encode("utf-8")).hexdigest()


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
        unknown: list[str] = []
        unreadable_levels: list[tuple[str, str]] = []
        shadowed_roots = _shadowed_builtin_roots(ctx.project_modules)
        for deco in entity.node.decorator_list:
            # The per-module census rides in on ``SeedContext`` and the reference site is
            # the decorated ``def``/``async def`` statement this entity already holds, so
            # P3 form 5 can evaluate in the provider.
            #
            # ``_match``'s argument list and its THREE-element verdict are Task 5
            # Step 3's; that step governs the exact spelling. This step changes only
            # the unpacking and adds the fourth arm below.
            ft, unprov, unreadable = self._match(
                deco,
                ctx.alias_map,
                shadowed_roots,
                census=ctx.census,
                reference_site=entity.node,
            )
            if ft is not None:
                candidates.append(ft)
            elif unprov is not None:
                # A CUSTOM BoundaryType's unreadable level value stays HERE: it keeps
                # WLN-ENGINE-UNPROVABLE-BOUNDARY and its UNKNOWN_RAW seed and NEVER
                # enters the residual list. One unreadable value takes exactly one
                # channel, which is what keeps decorator_coverage from counting the
                # same site twice (spec §4.2.1, soundness condition 5).
                unprovable.append(unprov)
            else:
                marker = unknown_vocabulary_marker(deco, ctx.alias_map, shadowed_roots)
                if marker is not None:
                    unknown.append(marker)
                elif unreadable:
                    # FOURTH ARM — a BUILTIN marker whose ArgKind.LEVEL value the shared
                    # reader could not read after P3 form 5. Mutually exclusive with the
                    # unknown probe by construction, not by precedence: the marker
                    # resolved to an exact REGISTRY export, so unknown_vocabulary_marker
                    # returned None for it. The population is what SURVIVES the shape
                    # gate — Task 5 runs call_shape_offences BEFORE the levels loop, so a
                    # shape-malformed marker drops its seed with no level read and takes
                    # PY-WL-130, never this arm.
                    unreadable_levels.extend(unreadable)
        if not candidates:
            # No proven seed. Any matched-but-unreadable CUSTOM boundaries are surfaced
            # (T2.4) and the L1 fallback seeds UNKNOWN_RAW (source="default", not
            # anchored — there is no usable declaration). Builtins never set ``unprov``.
            return SeedResult(
                taint=None,
                unprovable_boundaries=tuple(unprovable),
                unknown_markers=tuple(unknown),
                unreadable_level_values=tuple(unreadable_levels),
            )
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
        return SeedResult(
            taint=FunctionTaint(body, ret),
            unprovable_boundaries=tuple(unprovable),
            unknown_markers=tuple(unknown),
            unreadable_level_values=tuple(unreadable_levels),
        )

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
        *,
        census: ModuleCensus | None,
        reference_site: ast.stmt,
    ) -> tuple[FunctionTaint | None, str | None, tuple[tuple[str, str], ...]]:
        """Match one decorator against the loaded boundary types. Returns:

        ``(seed, None, ())``   — a boundary type matched and its levels proved;
        ``(None, name, ())``   — a CUSTOM type matched but a required level was
                                 unreadable (fail-closed; surfaced as a FACT). Builtins
                                 return ``(None, None, ...)`` here to stay silent
                                 (oracle-preserving);
        ``(None, None, ())``   — no boundary type matched (not vocabulary — 'no opinion').

        Shape offences (``call_shape_offences``) drop the seed before any level is read —
        so a marker that is BOTH shape-malformed and value-unreadable takes ``PY-WL-130``
        alone and never also ``WLN-ENGINE-UNREADABLE-MARKER-VALUE``.

        ``(None, None, pairs)`` — a BUILTIN marker whose ``ArgKind.LEVEL`` value stays
        unreadable; ``pairs`` carries ``(argument name, ast.unparse(value))`` RAW, for the
        residual FACT to normalise and truncate at emission.

        ``census`` and ``reference_site`` are REQUIRED keyword parameters carrying NO
        default: a defaulted-empty census ships the one-sided false green spec §4.2.1
        names, and without the reference site P3 form 5 cannot evaluate its
        lexical-precedence clause.
        """
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None:
            return None, None, ()
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
            if bt.builtin:
                entry = REGISTRY[bt.canonical_name]
                required = frozenset(la.arg_name for la in bt.level_args if la.default is None)
                if call_shape_offences(
                    deco,
                    call_form=entry.call_form,
                    declared=entry.kwargs,
                    required=required,
                ):
                    # Malformed builtin shape: the seed drops and the provider stays
                    # SILENT. PY-WL-130 is the loud channel (Task 6), and it is an
                    # ERROR, so a malformed marker cannot ship green.
                    #
                    # Deliberately NOT demoted to UNKNOWN_RAW when a provable sibling
                    # marker exists. Measured at release/2.0.0: UNKNOWN_RAW is in
                    # RAW_ZONE, modulate() returns Severity.NONE for it, and PY-WL-101
                    # skips a declared tier in RAW_ZONE — so demoting SILENCES every
                    # tier-gated rule on the function. Dropping the malformed marker and
                    # letting the provable one stand is strictly louder: the motivating
                    # stack (@trusted(level='ASSURED') over @external_boundary(source=…))
                    # seeds EXTERNAL_RAW today and fires ZERO ERROR+ defects, whereas
                    # after this change it seeds ASSURED and fires PY-WL-101 +
                    # PY-WL-112 — because declaring trust is what SUBJECTS a function to
                    # the leak rules.
                    #
                    # This return is ALSO the short-circuit that keeps a malformed
                    # marker off the residual channel: the shape verdict is decided
                    # here, BEFORE any level is read, so a marker that is both
                    # shape-malformed and value-unreadable never reaches the reader
                    # and never also takes WLN-ENGINE-UNREADABLE-MARKER-VALUE
                    # (spec §4.2.1). The residual tuple is empty for that reason.
                    return None, None, ()
            # The `(argument name, unparsed value text)` pair spec §4.2.1 condition 4
            # fingerprints on arrives on `LevelRead.unreadable_value` — Task 2's
            # discriminated return type, which is THE mechanism this plan names for
            # reaching it. The old bare `TaintState | None` answered `None` for BOTH
            # an unreadable value and a token that WAS read and then rejected by the
            # `allowed` check, and only the FIRST takes the residual FACT; the second
            # is PY-WL-114's DEFECT (spec §4.2.1's READS-then-rejects row) and must
            # never also emit a FACT. `LevelRead` is what keeps them apart, and the
            # provider does NOT re-read the value to work it out.
            levels: dict[str, TaintState] = {}
            unreadable = False
            unreadable_level_values: list[tuple[str, str]] = []
            for la in bt.level_args:
                read = _read_level(
                    deco,
                    la.arg_name,
                    declared=(
                        REGISTRY[bt.canonical_name].kwargs
                        if bt.builtin
                        else frozenset(item.arg_name for item in bt.level_args)
                    ),
                    allowed=la.allowed,
                    default=la.default,
                    alias_map=alias_map,
                    census=census,
                    reference_site=reference_site,
                    shadowed_roots=shadowed_roots,
                    builtin=bt.builtin,
                )
                if read.verdict is not LevelVerdict.RESOLVED:
                    unreadable = True
                    if read.unreadable_value is not None:
                        # `unreadable_value` is populated ONLY on verdict UNREADABLE
                        # AND builtin — the reader's own gate, so no caller-side
                        # builtin test is needed or wanted here. A CUSTOM
                        # BoundaryType therefore never contributes a pair: form 5 and
                        # the residual FACT are both builtin-only (spec §4.2's
                        # compatibility boundary, §4.2.1), so a custom type keeps
                        # `(None, canonical_name)` below with an EMPTY residual tuple,
                        # keeps WLN-ENGINE-UNPROVABLE-BOUNDARY and an UNKNOWN_RAW
                        # seed, and is never counted on two channels. A REJECTED
                        # verdict likewise carries no pair, on either side.
                        #
                        # Stored RAW. NFC normalisation and the 200-character
                        # truncation of spec §4.2.1 condition 4 apply to the
                        # VALUE-TEXT part only and are applied at the FACT emission
                        # site, never here.
                        unreadable_level_values.append(read.unreadable_value)
                    # ARITY CAP, SCOPED TO ``_match``'s OWN RETURN VALUE: this ``break``
                    # leaves the levels loop on the FIRST non-RESOLVED verdict, so the
                    # tuple THIS CALL returns holds at most one pair despite its
                    # ``tuple[tuple[str, str], ...]`` type.
                    #
                    # THE CAP STOPS HERE AND DOES NOT REACH THE PUBLIC FIELDS.
                    # ``taint_for`` EXTENDS across the whole decorator list, so
                    # ``SeedResult.unreadable_level_values`` and
                    # ``FunctionSeed.unreadable_level_values`` are UNBOUNDED — measured on
                    # this tree, ``@trusted(level=DYN)`` stacked over
                    # ``@trust_boundary(to_level=DYN)`` yields
                    # ``(('level', 'DYN'), ('to_level', 'DYN'))``. A consumer of those
                    # fields MUST iterate; reading ``values[0]`` silently drops every FACT
                    # after the first — a fail-open on this observability channel.
                    break
                # `LevelVerdict.RESOLVED` stays the semantic gate; this is the TYPE
                # obligation, not a second decision. Task 2's `LevelRead` contract is
                # that RESOLVED carries the level, but mypy performs no correlated
                # narrowing from `verdict` onto `level`, and `[assignment]` is
                # disabled for `tests` only, never for `src/`.
                assert read.level is not None
                levels[la.arg_name] = read.level
            if unreadable:
                return (
                    None,
                    (None if bt.builtin else bt.canonical_name),
                    tuple(unreadable_level_values),
                )
            return bt.seed(levels), None, ()
        return None, None, ()
