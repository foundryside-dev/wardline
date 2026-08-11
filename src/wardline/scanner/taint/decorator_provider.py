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
import itertools
import json
import re
import sys
from types import CodeType, MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Any

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
    from collections.abc import Callable, Iterable, Mapping

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
    memoization: ``active`` breaks cycles, ``memo`` records the ORDINAL of an object
    already expanded on this walk. ``alive`` pins every memoized object for the
    duration so CPython cannot recycle an ``id()`` underneath the memo.

    CORRECTED — this docstring previously claimed the memo made "the cost linear in the
    number of DISTINCT reachable objects rather than exponential in the paths to them".
    That is true of TRAVERSAL and **false of the preimage**: the memo shared a record by
    REFERENCE while ``json.dumps`` serialises it by VALUE at every occurrence, so a DAG
    was written out as a tree. Measured on a seed referencing ``click.Command``: 425
    distinct objects, **668 MiB of preimage in 4.6 s**. ``_MAX_EXPANDED_NODES`` bounds
    the node count (425 of 20 000 used) and therefore bounds nothing about cost. The
    memo now returns a BACK-REFERENCE, which is the same argument the ``cycle``
    back-edge already makes: the structure is in the preimage once, so a body change
    still moves the digest, and the preimage is linear in distinct objects for real.
    """

    __slots__ = ("active", "alive", "budget", "memo", "ordinal")

    def __init__(self) -> None:
        # id(obj) -> (ordinal of its FULL record, structural hash of that record).
        self.memo: dict[int, tuple[int, str]] = {}
        self.alive: list[object] = []
        self.active: set[int] = set()
        self.budget: int = _MAX_EXPANDED_NODES
        self.ordinal: int = 0


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
    """Memoized, cycle-safe, budgeted structural expansion of one object.

    A second reach of an already-expanded object returns a BACK-REFERENCE rather than
    the record again. Returning the record re-serialised the whole subtree at every
    occurrence — a DAG written out as a tree — which is how one ``click.Command``
    reference produced a 668 MiB preimage from 425 objects. The soundness argument is
    the one the ``cycle`` arm already relies on: the object's full structure is in the
    preimage exactly once, under a stated ordinal, so any change to it still moves the
    digest; the back-reference records only WHERE in the graph the sharing occurs.
    """
    key = id(value)
    seen = walk.memo.get(key)
    if seen is not None:
        # The back-reference carries the object's full STRUCTURAL HASH, not just a
        # pointer to where the record was emitted. Without ``h`` the back-reference
        # depends on the inline record surviving, and it does not always: the walk
        # reaches some objects twice and keeps only the second result (measured —
        # ``_instance_identity`` expanded ``__wrapped__`` once from the instance dict
        # and again explicitly, and the back-reference OVERWROTE the real body, so an
        # ``@lru_cache`` helper silently collided). A guard that discards a subtree
        # (``_contents``, ``_reduced_state``) can drop one the same way. Keying the
        # hash makes every back-reference discriminate on its own.
        ordinal, digest = seen
        return {"t": "seen", "n": ordinal, "h": digest, **_named(value)}
    if key in walk.active:
        # A reference cycle. The back-edge carries the NAME only; the object's own
        # structure is already being expanded higher up this same path, so the
        # structure is in the preimage exactly once and a body change still moves it.
        return {"t": "cycle", **_named(value)}
    if walk.budget <= 0:
        return {"t": "budget-exhausted", **_named(value)}
    walk.budget -= 1
    ordinal = walk.ordinal
    walk.ordinal += 1
    walk.active.add(key)
    try:
        record = build(depth)
    finally:
        walk.active.discard(key)
    walk.alive.append(value)
    # Hashed BEFORE the ordinal is attached, so ``h`` is a pure structural digest of
    # the object and carries no traversal-position information.
    walk.memo[key] = (ordinal, hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest())
    # The ordinal binds every back-reference to exactly this expansion, so two
    # same-named objects cannot share one. It makes the digest sensitive to TRAVERSAL
    # ORDER, which is why every container is now walked in a process-stable order —
    # see ``_set_order_key``.
    record["n"] = ordinal
    return record


def _code_of(value: object) -> CodeType | None:
    """The object's ``__code__``, but ONLY if it really is a code object.

    Every duck-typing probe in this module has to validate what it gets back. A
    permissive ``__getattr__`` answers EVERY name — measured on an ordinary pack, an
    instance with ``def __getattr__(self, name): return TaintState.EXTERNAL_RAW``
    answered ``__code__`` and the digest tried to read ``co_argcount`` off a
    ``TaintState``, raising ``AttributeError`` out of ``fingerprint()`` and taking the
    whole scan down. Probe, then check the type.
    """
    code = getattr(value, "__code__", None)
    return code if isinstance(code, CodeType) else None


def _has_code(value: object) -> bool:
    return _code_of(value) is not None


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


def _is_structurally_opaque_module(module: ModuleType) -> bool:
    """Fence for a MODULE, keyed on its own name rather than its ``__module__``."""
    name = str(getattr(module, "__name__", "") or "")
    return (not name) or name.split(".", 1)[0] in _OPAQUE_PACKAGES


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


def _snapshot(items: Callable[[], Iterable[Any]]) -> list[Any]:
    """Materialise a container's members BEFORE recursing into any of them.

    Expanding a member can WRITE to the container being iterated. The measured case is
    an ordinary idiom — a self-referential singleton, ``Policy.DEFAULT = Policy(1)``,
    which ``rich.console.Console`` also uses: expanding ``DEFAULT`` reaches
    ``__reduce_ex__(2)``, which asks ``copyreg._slotnames``, which writes
    ``__slotnames__`` into ``vars(Policy)`` — the very dict the class walk is iterating.
    ``RuntimeError: dictionary changed size during iteration``, out of ``fingerprint()``.

    Round 4 filtered ``__slotnames__` out of the class record's OUTPUT and left the
    WRITE in place, so it treated the symptom. The rule is the fix: never hold a live
    iterator over a container across a recursive expansion. Applied to every container
    the walk descends into, not only to the one that was measured.
    """
    return list(items())


def _set_order_key(value: object) -> str:
    """A cheap, process-STABLE ordering key for set members, computed without recursing.

    Set iteration order depends on hash values, which for ``str`` follow
    ``PYTHONHASHSEED`` and for plain objects follow allocation. That never mattered
    while records were shared by value — the members were sorted by canonical JSON
    afterwards, so the output was order-independent either way. It matters NOW: with
    back-references, WHICH occurrence carries the full record is decided by traversal
    order, so an unstable traversal would make the digest differ between processes.
    Sorting the members first makes the traversal deterministic; the post-recursion
    sort by canonical JSON is still applied, so the OUTPUT stays canonical regardless.
    """
    return _canonical_json([type(value).__name__, _named(value), _safe_repr(value)])


def _contents(build: Callable[[], object]) -> object:
    """Extract a container's CONTENTS, or degrade — never raise out of the digest.

    Iterating a value calls PACK code the moment that value is a subclass: a global
    ``class H(dict): def items(self): raise`` reaches ``_seed_value_identity``
    through ``_function_identity``'s globals loop, which has no guard around it, and
    the exception left ``fingerprint()`` and took the whole scan down. Measured on
    ``dict``, ``list``, ``set`` and ``tuple`` subclasses. This is the THIRD instance of
    the same crash class in this file (``__code__``, then ``__next__``), so it is
    closed here as a rule for every content-extracting arm rather than per shape.

    The degradation is safe in the direction that matters: the record still carries
    ``type`` through ``_typed_shape``, which for a subclass is where the behaviour is.
    """
    try:
        return build()
    except Exception:  # noqa: BLE001 — hostile container internals must not break the digest
        return {"t": "unreadable-contents"}


def _typed_shape(value: object, record: dict[str, object], walk: _Walk, depth: int) -> dict[str, object]:
    """Attach the value's TYPE to a shape-matched record, unless the type is fenced.

    THE GENERAL FORM of every defect found in rounds 0-3: an arm that matches on
    SHAPE and returns a contents-or-name proxy before any structural arm, consulting
    no fence. ``isinstance`` catches subclasses, and a subclass body is grammar
    behaviour — ``class P(NamedTuple): ... def decide(self): ...`` is ordinary Python.
    Measured COLLIDE on a ``decide`` body change for tuple/list/set/dict/str
    subclasses, for a ``str``-mixin ``Enum`` member, and for a pack's own
    ``__func__``-bearing wrapper class.

    Applied as an ADDITIVE key rather than by falling through to the instance arm:
    falling through would swap a shape's contents (``v``) for its pickle payload and
    could NARROW coverage on shapes no row measures, whereas adding a key cannot. A
    value whose type is fenced (``builtins``/stdlib/``wardline`` — a plain ``tuple``,
    ``str``, ``dict``…) gets a byte-identical record, so no ordinary grammar's digest
    moves and no warm cache goes cold.
    """
    cls = type(value)
    if not _is_structurally_opaque(cls):
        record["type"] = _seed_value_identity(cls, walk, depth)
    return record


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
    # supertypes or they collapse into the str/int arms. Neither is subclassable
    # (``TaintState`` has members; ``bool`` is not an acceptable base type), so
    # neither arm can be reached by a subclass carrying a body — verified, not assumed.
    if isinstance(value, TaintState):
        return {"t": "taint", "v": value.value}
    if isinstance(value, FunctionTaint):
        return _typed_shape(
            value,
            {
                "t": "function_taint",
                "body": _seed_value_identity(value.body_taint, walk, d),
                "return": _seed_value_identity(value.return_taint, walk, d),
            },
            walk,
            d,
        )
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    # The BASE class's unbound method, never ``str()``/``repr()``: a subclass may
    # override ``__str__``/``__repr__``, which would both crash the digest and let the
    # scalar's canonical encoding be chosen by pack code. Byte-identical for an
    # ordinary ``int``/``float``/``complex``.
    if isinstance(value, int):
        return _typed_shape(value, {"t": "int", "v": int.__repr__(value)}, walk, d)
    if isinstance(value, float):
        return _typed_shape(value, {"t": "float", "v": float.__repr__(value)}, walk, d)
    if isinstance(value, complex):
        return _typed_shape(value, {"t": "complex", "v": complex.__repr__(value)}, walk, d)
    if isinstance(value, str):
        # A ``str`` MIXIN ENUM member (``class L(str, Enum)``) lands here, and its
        # class carries the methods a seed calls. Measured COLLIDE before the gate.
        return _typed_shape(value, {"t": "str", "v": value}, walk, d)
    if isinstance(value, (bytes, bytearray)):
        return _typed_shape(value, {"t": "bytes", "v": _contents(lambda: bytes(value).hex())}, walk, d)
    # ``CodeType`` is not an acceptable base type, so this arm cannot be reached by a
    # subclass carrying a body — verified, not assumed.
    if isinstance(value, CodeType):
        # Nested code (an inner def/lambda/comprehension lands in ``co_consts``)
        # recurses into the SAME structural normalization. ``repr(code)`` is not an
        # accepted canonical form: it embeds the object's memory ADDRESS and its
        # source filename/first line, so it is simultaneously unstable across
        # processes and sensitive to pure layout.
        return {"t": "code", "v": _code_identity(value, walk, d)}
    if isinstance(value, ModuleType):
        # Reached with no demand information (from a closure cell, a class attribute, a
        # container): keyed by NAME. Reached from a function's globals — the shape that
        # matters — the caller resolves the ATTRIBUTES that function actually uses; see
        # ``_module_identity`` and its call site in ``_function_identity``.
        return _typed_shape(value, {"t": "module", "v": str(getattr(value, "__name__", "") or "")}, walk, d)
    if isinstance(value, (tuple, list)):
        # ``type(value).__name__`` is a NAME, and a ``tuple``/``list`` SUBCLASS carries
        # a body: ``class P(NamedTuple): ... def decide(self): ...`` measured COLLIDE.
        return _typed_shape(
            value,
            {
                "t": type(value).__name__,
                # SNAPSHOT before recursing: expanding a member can WRITE to the
                # container being iterated (see ``_snapshot``).
                "v": _contents(lambda: [_seed_value_identity(v, walk, d) for v in _snapshot(lambda: value)]),
            },
            walk,
            d,
        )
    if isinstance(value, (frozenset, set)):
        return _typed_shape(
            value,
            {
                "t": type(value).__name__,
                # Members are sorted BEFORE recursion, so traversal is process-stable
                # and a back-reference lands in the same place every run; the records
                # are sorted again AFTER, so the emitted order stays canonical.
                "v": _contents(
                    lambda: sorted(
                        (
                            _seed_value_identity(v, walk, d)
                            for v in sorted(_snapshot(lambda: value), key=_set_order_key)
                        ),
                        key=_canonical_json,
                    )
                ),
            },
            walk,
            d,
        )
    if isinstance(value, (dict, MappingProxyType)):
        # ``MappingProxyType`` is NOT a ``dict`` subclass, so it used to miss this arm
        # and fall through to ``repr`` — which is how ``functools.singledispatch``'s
        # ``registry`` (a mappingproxy of type -> implementation) hid every registered
        # implementation behind an address-normalised string.
        # NOTE: the round-3 pass changed this tag from the literal ``"dict"`` to
        # ``type(value).__name__`` WITHOUT gating it — reproducing the very pattern it
        # was fixing. A name is not a body; ``class D(dict)`` with a method measured
        # COLLIDE until ``_typed_shape`` was added here.
        return _typed_shape(
            value,
            {
                "t": type(value).__name__,
                "v": _contents(
                    lambda: sorted(
                        (
                            [_seed_value_identity(k, walk, d), _seed_value_identity(v, walk, d)]
                            for k, v in _snapshot(value.items)
                        ),
                        key=_canonical_json,
                    )
                ),
            },
            walk,
            d,
        )

    # --- Structural arms: a referenced FUNCTION or CLASS is keyed by its BODY --------
    #
    # Keying a referenced global by ``module.qualname`` alone is a measured cache-
    # poisoning hole, and it is the LIVE path: a production pack loads as a real
    # importable module, so `def seed(levels): return _helper(levels)` is the ordinary
    # shape. Under a name-only key, editing `_helper` to return ASSURED instead of
    # EXTERNAL_RAW leaves the digest byte-identical and a warm cache answers the new
    # grammar with the old grammar's verdicts. The body has to be in the preimage.
    # staticmethod / classmethod / BOUND METHOD wrappers around a real function. This
    # arm MUST precede the plain-function arm: a bound method carries BOTH ``__code__``
    # and ``__func__``, so tested second it matched as a bare function and its
    # ``__self__`` — the receiver holding the configuration the method reads, as in
    # ``DECIDE = Policy(EXTERNAL_RAW).decide`` — was silently dropped. Measured COLLIDE.
    inner = getattr(value, "__func__", None)
    if inner is not None and _has_code(inner):
        bound_self = getattr(value, "__self__", None)
        # ``wrapper`` is a NAME, and for ``staticmethod``/``classmethod``/``method``
        # (all ``builtins``, all fenced) that is all there is. A PACK's own wrapper
        # class — ``class W: def __init__(self, fn): self.__func__ = fn`` with its own
        # ``__call__`` — also matches this arm, and its ``__call__`` body is the
        # behaviour. Measured COLLIDE until ``_typed_shape`` expanded the wrapper type.
        return _typed_shape(
            value,
            {
                "t": "wrapped_function",
                "wrapper": type(value).__name__,
                "v": _seed_value_identity(inner, walk, d),
                "self": _seed_value_identity(bound_self, walk, d) if bound_self is not None else {"t": "none"},
            },
            walk,
            d,
        )
    if _has_code(value) and not _is_structurally_opaque(value):
        return _expanded(value, walk, d, lambda dd: _function_identity(value, walk, dd))
    if isinstance(value, type) and not _is_structurally_opaque(value):
        return _expanded(value, walk, d, lambda dd: _class_identity(value, walk, dd))
    if isinstance(value, property):
        # A ``property`` SUBCLASS may override ``__get__`` and compute the value itself,
        # in which case ``fget`` is not the behaviour — so the type is expanded too.
        return _typed_shape(
            value,
            {
                "t": "property",
                "fget": _seed_value_identity(value.fget, walk, d),
                "fset": _seed_value_identity(value.fset, walk, d),
                "fdel": _seed_value_identity(value.fdel, walk, d),
            },
            walk,
            d,
        )

    # NAME-ONLY arms, and they fire ONLY for objects the fence has already declared
    # out of scope. Ungated, they were a fail-open: ``functools.wraps`` /
    # ``update_wrapper`` COPY a str ``__module__`` and ``__qualname__` onto the wrapper,
    # so an ``@lru_cache``-decorated pack helper — and any class-based decorator using
    # ``functools.wraps`` — matched here and collapsed to the wrapped function's NAME,
    # never reaching the structural instance arm below. A name is not a body.
    if _is_structurally_opaque(value):
        module = getattr(value, "__module__", None)
        qualname = getattr(value, "__qualname__", None)
        ref: dict[str, object] | None = None
        if isinstance(module, str) and isinstance(qualname, str):
            ref = {"t": "ref", "module": module, "qualname": qualname}
        else:
            name = getattr(value, "__name__", None)
            if isinstance(module, str) and isinstance(name, str):
                ref = {"t": "ref", "module": module, "name": name}
        if ref is not None:
            if _has_code(value):
                # A fenced FUNCTION's BODY is versioned elsewhere, but the objects it
                # CAPTURES are not: ``contextlib.ExitStack.callback`` stores a
                # ``contextlib``-defined ``_exit_wrapper`` closure whose cell holds the
                # PACK's helper, and the name-only ref hid it (measured COLLIDE). The
                # bindings are added; the body and globals are still fenced out, so the
                # cost/stability property the fence exists for is untouched. Routed
                # through ``_expanded`` for the cycle and memo guards the direct return
                # did not have.
                base = ref
                return _expanded(value, walk, d, lambda dd: {**base, **_ref_bindings(value, walk, dd)})
            return ref
    # INSTANCE ARM. An instance must not HIDE the class that gives it behaviour.
    #
    # The ordinary pack shape hoists the instantiation to module scope:
    #
    #     POLICY = Policy(1)
    #     def seed(l): return FunctionTaint(POLICY.decide(l), ...)
    #
    # ``Policy`` is then absent from the seed's ``co_names`` — only ``POLICY`` and
    # ``decide`` appear — so the class arm above is NEVER reached through this path.
    # Keyed by ``repr`` alone, neither the method body nor the instance state entered
    # the preimage, and normalising the address out of that ``repr`` made two
    # differently-CONFIGURED instances collide outright. So the instance is keyed
    # STRUCTURALLY: its type (through the fenced class arm, so a pack class is expanded
    # and a stdlib one stays a name), its instance state, its PICKLE-protocol state, and
    # its normalised ``repr`` — four sources because no one of them is sufficient.
    #
    # CORRECTED: an earlier revision of this comment claimed ``repr`` was retained
    # because it carries "the C-level content of objects with no readable
    # ``__dict__``/``__slots__`` (``functools.partial``'s target and bound arguments,
    # for one)". Measured, that is false — ``repr(partial)`` prints the target's NAME
    # only, so changing the target's BODY collided. ``__reduce_ex__`` is what actually
    # reaches that content; ``repr`` is retained as a genuine last resort, nothing more.
    return _expanded(value, walk, d, lambda dd: _instance_identity(value, walk, dd))


def _ref_bindings(value: object, walk: _Walk, depth: int) -> dict[str, object]:
    """What a FENCED function CAPTURES — never what it does.

    The fence's licence is that a stdlib/``wardline`` function's BODY is versioned by
    the interpreter or by ``_RESOLVER_VERSION``/``REGISTRY_VERSION``. That licence does
    not extend to the objects the function has captured, which come from the PACK:
    ``contextlib.ExitStack.callback`` hands back a ``contextlib`` closure holding the
    pack's helper in a cell. Only closure cells, defaults and function attributes are
    read — NOT ``__globals__`` and NOT the code — so the 207 MB / process-unstable
    namespace walk the fence exists to prevent stays prevented.

    Restricted to functions on purpose: a fenced CLASS's ``__dict__`` is its whole
    stdlib namespace, and walking that is exactly what the fence forbids.
    """
    if not _has_code(value):
        return {}
    extra: dict[str, object] = {}
    cells = _closure_identity(value, walk, depth)
    if cells:
        extra["closure"] = cells
    defaults = getattr(value, "__defaults__", None)
    if defaults:
        extra["defaults"] = _seed_value_identity(defaults, walk, depth)
    kwdefaults = getattr(value, "__kwdefaults__", None)
    if kwdefaults:
        extra["kwdefaults"] = _seed_value_identity(kwdefaults, walk, depth)
    attrs = getattr(value, "__dict__", None)
    if isinstance(attrs, dict) and attrs:
        extra["attrs"] = _seed_value_identity(attrs, walk, depth)
    # Keys are OMITTED when empty so an ordinary fenced ref stays byte-identical to
    # what it was — no digest of an existing grammar moves for a capture-free helper.
    return extra


def _slot_names(cls: type) -> list[str]:
    """Every ``__slots__`` name declared anywhere in a type's MRO, deduped and ordered."""
    names: list[str] = []
    for klass in getattr(cls, "__mro__", ()):
        declared = klass.__dict__.get("__slots__", ())
        if isinstance(declared, str):
            declared = (declared,)
        try:
            # ``__slots__`` may be any iterable, including pack code that raises.
            for slot in declared:
                if isinstance(slot, str) and slot not in names:
                    names.append(slot)
        except Exception:  # noqa: BLE001 — a hostile __slots__ must not break the digest
            continue
    return sorted(names)


def _safe_repr(value: object) -> str:
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001 — a hostile __repr__ must not break the digest
        return "<unreprable>"
    # A memory address is process noise, never durable information, and leaving it in
    # made every grammar that reached such an object cold-cache on every run. The
    # DISCRIMINATION that address appeared to provide is restored structurally by the
    # type and state fields beside this one — the address itself never carried it.
    return _ADDRESS_RE.sub(" at 0x<addr>", text)


def _reduced_state(value: object, walk: _Walk, depth: int) -> object:
    """C-level state via the PICKLE protocol — Python's own answer to "what is in here".

    ``__dict__`` and ``__slots__`` see nothing inside a C object. ``functools.partial``
    is the measured case: ``state`` is ``{}``, its ``type`` is fenced to ``functools``,
    and its ``repr`` prints only the target's NAME, so changing the target function's
    BODY collided. ``__reduce_ex__`` yields the target, the bound args and the keywords
    as real objects, which then expand structurally like anything else. Guarded: a
    reduce that raises, or is absent, simply contributes nothing.
    """
    try:
        reduced = value.__reduce_ex__(2)
    except Exception:  # noqa: BLE001 — an unpicklable object must not break the digest
        return {"t": "no-reduce"}
    if isinstance(reduced, str):
        return {"t": "str", "v": reduced}
    if not isinstance(reduced, tuple):
        return {"t": "no-reduce"}
    # Element 0 is the reconstructor callable (the class, or copyreg._reconstructor);
    # the payload that distinguishes two instances is everything after it.
    #
    # The comprehension is INSIDE the guard, not outside it. The ``try`` above used to
    # cover only the ``__reduce_ex__`` call, so a hostile or merely unusual reduce
    # PAYLOAD raised out of ``fingerprint()`` and took the whole scan down — the same
    # crash class as the ``__code__`` probe, inside the code that fixes probes. The
    # marker is DISTINCT from ``no-reduce`` so the two degradations stay
    # distinguishable in a preimage; both under-discriminate and are named residuals.
    try:
        return [_reduce_part(part, walk, depth) for part in reduced[1:]]
    except Exception:  # noqa: BLE001 — an unreadable reduce payload must not break the digest
        return {"t": "unreadable-reduce"}


# Slots 3 and 4 of a reduce tuple are the "listitems"/"dictitems" ITERATORS through
# which a C container hands pickle its contents. Measured: a ``collections.deque``
# holding a pack helper collided, because those items live in C storage that
# ``__dict__``, ``__slots__`` and the reduce ARGS tuple all miss. The cap is a guard
# against a pathological custom ``__reduce__``, set far above any real container.
_MAX_REDUCE_ITEMS = 100_000


def _reduce_part(part: object, walk: _Walk, depth: int) -> object:
    """One element of a reduce tuple, draining the item iterators."""
    # Probe the TYPE, never the instance: a permissive ``__getattr__`` answers every
    # name, and this module has already been bitten once by an unvalidated probe.
    #
    # ``__next__`` ALONE was itself an unvalidated probe — the very defect this helper
    # was written to fix, reproduced one line down. ``islice`` calls ``iter()``, so a
    # type with ``__next__`` and no ``__iter__`` (reachable through a custom
    # ``__reduce__``) raised ``TypeError`` out of ``fingerprint()``. Both names are
    # required now, and the drain is guarded besides.
    part_type = type(part)
    if hasattr(part_type, "__next__") and hasattr(part_type, "__iter__"):
        # These iterators are created BY the ``__reduce_ex__`` call, so draining one
        # consumes a fresh object and cannot disturb the container itself.
        try:
            items = list(itertools.islice(part, _MAX_REDUCE_ITEMS))  # type: ignore[call-overload]
        except Exception:  # noqa: BLE001 — a hostile iterator must not break the digest
            return {"t": "undrainable-items"}
        return {"t": "reduce-items", "v": [_seed_value_identity(item, walk, depth) for item in items]}
    return _seed_value_identity(part, walk, depth)


def _instance_identity(value: object, walk: _Walk, depth: int) -> dict[str, object]:
    """Structural record for an ordinary object: type, state, reduced state, and repr.

    Four sources because no one of them is sufficient, which is the lesson of the last
    three review rounds: ``type`` carries the class and metaclass bodies (and so covers
    ``__getattr__``- and ``property``-computed behaviour, whose CODE lives on the
    class); ``state`` carries ``__dict__``/``__slots__`` configuration; ``reduced``
    carries C-level payload neither of those sees; and ``repr`` is the last-resort
    catch for anything all three miss.
    """
    state: dict[str, object] = {}
    instance_dict = getattr(value, "__dict__", None)
    if isinstance(instance_dict, dict):
        # SNAPSHOT: expanding a value can set another attribute on the same instance.
        for key, item in _snapshot(instance_dict.items):
            state[str(key)] = _seed_value_identity(item, walk, depth)
    for slot in _slot_names(type(value)):
        if slot in state:
            # Already carried by ``__dict__``; re-expanding would replace the inline
            # record with a back-reference and move the structure out of this subtree.
            continue
        try:
            state[slot] = _seed_value_identity(getattr(value, slot), walk, depth)
        except AttributeError:
            state[slot] = {"t": "unset-slot"}
        except Exception:  # noqa: BLE001 — a slot name shadowed by a raising property
            # An unset slot and an unreadable one are DIFFERENT degradations; only the
            # first is normal. Reading a slot runs pack code whenever a subclass
            # shadows the name with a property, so this must not escape the digest.
            state[slot] = {"t": "unreadable-slot"}
    # The documented decorator-transparency protocol. ``functools.wraps`` sets it, and
    # following it is what reaches the real body through an opaque wrapper. The probe
    # is guarded: ``getattr``'s default only swallows ``AttributeError``, and a
    # permissive or hostile ``__getattr__`` can raise anything at all.
    try:
        wrapped = getattr(value, "__wrapped__", None)
    except Exception:  # noqa: BLE001 — a hostile __getattr__ must not break the digest
        wrapped = None
    if wrapped is not None and "__wrapped__" not in state:
        state["__wrapped__"] = _seed_value_identity(wrapped, walk, depth)
    return {
        "t": "instance",
        "type": _seed_value_identity(type(value), walk, depth),
        "state": state,
        "reduced": _reduced_state(value, walk, depth),
        "repr": _safe_repr(value),
    }


def _reachable_names(code: CodeType) -> tuple[str, ...]:
    """Every global name the function can reach — ITS ``co_names`` plus every nested one.

    A ``lambda``, a generator expression and an inner ``def`` each compile to their own
    code object in ``co_consts``, and the names they use live in THAT object's
    ``co_names``, not the outer one's. Resolving globals against the outer names alone
    left a helper used only from inside one of them as a bare name in the preimage, so
    two behaviourally different grammars shared a cache key. Measured COLLIDE for a
    genexp and for an inner ``def``; the control (a direct call) discriminated.

    Returned SORTED, so the order the globals are expanded in — which now decides where
    a back-reference points — is fixed by the name set and not by compilation order.
    """
    found: set[str] = set()
    stack = [code]
    while stack:
        current = stack.pop()
        found.update(current.co_names)
        stack.extend(const for const in current.co_consts if isinstance(const, CodeType))
    return tuple(sorted(found))


def _function_identity(fn: object, walk: _Walk, depth: int) -> dict[str, object]:
    """Structural record for a function: its code, its bindings, and its globals."""
    code = _code_of(fn)
    assert code is not None  # callers gate on _has_code
    globals_map = getattr(fn, "__globals__", None)
    globals_record: dict[str, object] = {}
    names = _reachable_names(code)
    if isinstance(globals_map, dict):
        for name in names:
            if name not in globals_map:
                globals_record[name] = {"t": "missing-global"}
                continue
            target = globals_map[name]
            if isinstance(target, ModuleType) and not _is_structurally_opaque_module(target):
                # ``H.decide()`` — resolve the ATTRIBUTES this function names.
                globals_record[name] = _module_identity(target, names, walk, depth)
            else:
                globals_record[name] = _seed_value_identity(target, walk, depth)
    return {
        "kind": "function",
        **_named(fn),
        "code": _code_identity(code, walk, depth),
        "defaults": _seed_value_identity(getattr(fn, "__defaults__", None), walk, depth),
        "kwdefaults": _seed_value_identity(getattr(fn, "__kwdefaults__", None), walk, depth),
        "closure": _closure_identity(fn, walk, depth),
        "globals": globals_record,
        # Attributes set ON the function object. This is where a decorator parks the
        # state that IS the behaviour — ``functools.singledispatch`` keeps its
        # type -> implementation ``registry`` here, and ``functools.wraps`` its
        # ``__wrapped__``. Neither is reachable from code, closure or globals.
        "attrs": _seed_value_identity(getattr(fn, "__dict__", None), walk, depth),
    }


# Import machinery and filesystem paths in a module namespace: neither is behaviour,
# and ``__file__``/``__cached__``/``__spec__`` would re-break relocation stability.
# ``__builtins__`` alone is the entire builtin namespace.
_MODULE_NOISE = frozenset(
    {"__builtins__", "__loader__", "__spec__", "__file__", "__cached__", "__path__", "__package__", "__name__"}
)


def _module_identity(
    module: ModuleType,
    used: tuple[str, ...],
    walk: _Walk,
    depth: int,
    seen: frozenset[int] = frozenset(),
) -> dict[str, object]:
    """Structural record for a referenced module — DEMAND-DRIVEN, not a namespace walk.

    ``import mypack.helpers as H`` then ``H.decide()`` is an everyday grammar shape, and
    keying the module by NAME alone left every helper in it invisible (measured
    COLLIDE). But walking the whole namespace instead is not an option: measured on a
    pack that does ``import yaml as Y``, a full walk produced a **207 MB preimage in
    1.6 s** — deterministic, but unusable, and worse for a heavier dependency.

    The asymmetry is the point: following a REFERENCE is demand-driven and pulls only
    what the grammar uses, whereas walking a NAMESPACE pulls everything whether the
    grammar touches it or not. So only the attribute names that appear in the referring
    function's ``co_names`` are expanded — for ``H.decide()`` that is exactly
    ``decide``. Same coverage on the shapes that matter, bounded cost.

    Deliberately NOT memoized on the module's ``id()``: two functions may use different
    attributes of one module, and a memo keyed on the module alone would freeze the
    first function's attribute set and hide a change under any attribute the second one
    uses. Recursion still terminates — every function it reaches goes through
    ``_expanded``, and a module -> module edge is guarded by ``seen``.

    SUBMODULES recurse. ``import pkg as H`` then ``H.sub.decide()`` has
    ``co_names == ('H', 'sub', 'decide')`` — the demand information for BOTH hops is
    right there — but ``sub`` used to hit the name-only module arm of
    ``_seed_value_identity`` and every helper under it stayed invisible (measured
    COLLIDE). The same ``used`` tuple drives each hop, so the walk stays demand-driven.

    A demanded name that is ABSENT from the namespace records ``{"t": "missing"}``
    rather than being silently omitted, mirroring ``_function_identity``'s
    ``missing-global``. Silence made two DIFFERENT demand sets share a record. On its
    own that does NOT close module-level PEP-562 ``__getattr__`` — both sides are
    equally "missing" — so the module's ``__getattr__``, which is the code that
    actually computes the attribute, is keyed structurally beside it.
    """
    key = id(module)
    name = str(getattr(module, "__name__", "") or "")
    if key in seen or depth > _MAX_VALUE_DEPTH:
        # A module graph may be cyclic (``pkg.sub.pkg``); the structure is already on
        # this path, so the back-edge carries the name alone.
        return {"t": "module", "name": name, "cycle": True}
    seen = seen | {key}
    namespace = getattr(module, "__dict__", None)
    members: dict[str, object] = {}
    record: dict[str, object] = {"t": "module", "name": name, "members": members}
    if isinstance(namespace, dict):
        for want in sorted(set(used)):
            if want in _MODULE_NOISE:
                continue
            if want not in namespace:
                members[str(want)] = {"t": "missing"}
                continue
            target = namespace[want]
            if isinstance(target, ModuleType) and not _is_structurally_opaque_module(target):
                members[str(want)] = _module_identity(target, used, walk, depth + 1, seen)
            else:
                members[str(want)] = _seed_value_identity(target, walk, depth)
        module_getattr = namespace.get("__getattr__")
        if module_getattr is not None:
            # PEP 562. Never in ``co_names``, so demand cannot reach it; added by name.
            record["module_getattr"] = _seed_value_identity(module_getattr, walk, depth)
    return _typed_shape(module, record, walk, depth)


# Entries in a class namespace that are NOT declaration content:
#  * ``__firstlineno__`` — 3.13's class-level source line, pure layout noise;
#  * ``__slotnames__``   — ``copyreg``'s lazily-computed, class-CACHED slot list. It is
#    written by ``__reduce_ex__(2)``, i.e. by this digest's own traversal, which makes
#    the record depend on whether anything pickled the class earlier in the process.
_CLASS_NOISE = frozenset({"__firstlineno__", "__slotnames__"})


def _class_identity(cls: type, walk: _Walk, depth: int) -> dict[str, object]:
    """Structural record for a class: its own namespace, plus its bases.

    ``vars(cls)`` carries the method bodies (each expanded through the function arm
    above) AND the class-level data a seed's behaviour can turn on. ``__bases__`` is
    walked so a change to an INHERITED method also moves the digest — ``vars`` is
    own-dict only.

    ``__firstlineno__`` is dropped: since 3.13 CPython stores the class's source line
    in its namespace, and it is exactly the layout noise ``_code_identity`` excludes —
    left in, moving a class down a file would cold-invalidate every warm cache.

    ``__slotnames__`` is dropped, and that one is a MEASURED bug, not a tidy-up.
    ``copyreg`` computes it lazily during ``__reduce_ex__(2)`` and CACHES it onto the
    class — so ``_reduced_state`` MUTATES the very object graph it is hashing. On an
    ordinary slotted pack class, two ``fingerprint()`` calls in ONE process returned
    different digests: the first injected the key, the second saw it. Three rounds of
    stability checks missed it because every one of them compared FRESH processes,
    where both sides start equally uncached. It is derived purely from ``__slots__``,
    which ``_slot_names`` and these very members already key, so dropping it loses
    nothing.
    """
    # SNAPSHOT: ``vars(cls)`` is the LIVE class dict, and expanding a member writes to
    # it — ``Policy.DEFAULT = Policy(1)`` reaches ``copyreg._slotnames``, which inserts
    # ``__slotnames__`` into this very dict mid-iteration. Round 4 filtered the key out
    # of the output and left the write, so the crash survived.
    members = {
        str(k): _seed_value_identity(v, walk, depth) for k, v in _snapshot(vars(cls).items) if k not in _CLASS_NOISE
    }
    return {
        "kind": "class",
        **_named(cls),
        "members": members,
        "bases": [_seed_value_identity(b, walk, depth) for b in getattr(cls, "__bases__", ())],
        # A METACLASS carries behaviour that is in neither ``vars(cls)`` nor
        # ``__bases__``: ``Meta.__call__``, ``Meta.__getattr__``, ``Meta.decide``. Walking
        # bases alone left every one of those invisible.
        "metaclass": _seed_value_identity(type(cls), walk, depth),
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
    for cell in _snapshot(lambda: getattr(seed, "__closure__", None) or ()):
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

    A non-function callable (no ``__code__``) is keyed STRUCTURALLY, through the same
    instance arm every other object uses.

    CORRECTED — this arm used to return ``{"kind", "qualname", "repr"}`` with the RAW
    ``repr``, justified as "the repr embeds a memory address, so it over-invalidates,
    and over-invalidating is safe". That justification only holds for the DEFAULT
    ``repr``. A callable seed whose class defines ``__repr__`` — a dataclass, a
    ``NamedTuple``, an attrs class, or any hand-written ``__repr__`` — has a STABLE
    repr, so changing its ``__call__`` BODY left the digest byte-identical. Measured
    COLLIDE. It is the same general form as every other defect closed in this file: an
    arm matching on SHAPE that returns a proxy before any structural arm, consulting
    no fence.

    The old arm's stated fear — that keying on the CLASS would make two differently-
    CONFIGURED instances collide — is answered by the instance record itself, which
    carries ``state`` (``__dict__`` + ``__slots__``) and ``reduced`` beside ``type``.
    Dropping the address costs no discrimination it was really providing: an address
    changes every process, so a callable-object seed never warmed a cache at all. It
    is now process-stable AND body-sensitive, which is round 2's trade repeated on the
    one path round 2 left alone.
    """
    if walk is None:
        walk = _Walk()
    if not _has_code(seed):
        return {"kind": "opaque", "v": _seed_value_identity(seed, walk, 0)}
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
