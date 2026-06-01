# src/wardline/scanner/grammar.py
"""The extensible trust grammar (Track 2).

Generalizes Wardline's three hardcoded trust decorators and four hardcoded rules
into one open meta-model an agent can extend WITHOUT editing engine source, while
the builtin vocabulary keeps producing byte-identical findings.

Layering (preserved, load-bearing): a :class:`BoundaryType` feeds L1 seeding
(declaration -> taint); rules read the RESOLVED taint state, not the decorator. The
grammar registers both; it does not couple them per-instance. (See the design spec
§2 for why tighter coupling is rejected.)

Zero-dep: stdlib + ``core.taints`` + ``core.registry`` + the provider's
``FunctionTaint`` only. No new dependency, runtime, or config language — the
extension plane is a *code* seam, the same shape as ``TaintSourceProvider``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.scanner.context import _Rule  # the rule Protocol (rule_id + check)
from wardline.scanner.taint.provider import FunctionTaint

_VOCAB_PREFIX = "wardline.decorators"
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})


@dataclass(frozen=True, slots=True)
class LevelArg:
    """A statically-read keyword argument of a boundary marker (e.g. ``to_level``).

    ``default=None`` means the argument is REQUIRED: a missing / unreadable /
    out-of-``allowed`` value is a fail-closed seed (the provider returns the
    unprovable signal — for a custom boundary type that becomes an observable
    ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` FACT; builtins stay silent, preserving the
    byte-identity oracle).
    """

    arg_name: str
    allowed: frozenset[TaintState]
    default: TaintState | None


@dataclass(frozen=True, slots=True)
class BoundaryType:
    """A declared trust transition: a recognizable decorator marker + its L1 seed.

    ``module_prefix`` + ``canonical_name`` are how the engine RECOGNIZES the marker
    on a target's AST (alias-resolved) — e.g. ``wardline.decorators.trusted`` for a
    builtin, or ``myproj.trust.sanitized`` for an agent-defined one. ``level_args``
    is what the engine reads from the call site (generic machinery in the provider).
    ``seed`` maps the read levels to the function's seed taint. ``builtin`` gates the
    T2.4 unprovable FACT: builtins never emit it (oracle-preserving, design spec §4).

    The engine recognizes a custom marker purely by AST shape (prefix + name +
    readable kwargs); it never imports or executes the scanned target — a
    ``BoundaryType`` is *data describing how to read a marker*, not target code.
    """

    canonical_name: str
    module_prefix: str
    group: int
    level_args: tuple[LevelArg, ...]
    seed: Callable[[Mapping[str, TaintState]], FunctionTaint]
    builtin: bool = False


# --- Builtin boundary types: one source of truth, aligned with REGISTRY (spec §3) ---


def _seed_external(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)


def _seed_boundary(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _seed_trusted(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(levels["level"], levels["level"])


BUILTIN_BOUNDARY_TYPES: tuple[BoundaryType, ...] = (
    BoundaryType("external_boundary", _VOCAB_PREFIX, 1, (), _seed_external, builtin=True),
    BoundaryType(
        "trust_boundary",
        _VOCAB_PREFIX,
        1,
        (LevelArg("to_level", _BOUNDARY_LEVELS, default=None),),
        _seed_boundary,
        builtin=True,
    ),
    BoundaryType(
        "trusted",
        _VOCAB_PREFIX,
        1,
        (LevelArg("level", _TRUSTED_LEVELS, default=TaintState.INTEGRAL),),
        _seed_trusted,
        builtin=True,
    ),
)

# Consistency tripwire: builtin names/group must mirror the released REGISTRY so the
# two views (REGISTRY = declaration contract; grammar = + seed semantics) cannot drift.
for _bt in BUILTIN_BOUNDARY_TYPES:
    _entry = REGISTRY.get(_bt.canonical_name)
    if _entry is None or _entry.group != _bt.group:
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} drifted from REGISTRY")
del _bt, _entry


@dataclass(frozen=True, slots=True)
class TrustGrammar:
    """The wiring object: boundary types (feed L1 seeding) + rule classes (enforcement).

    ``rules`` are rule CLASSES (not instances) — they are instantiated per-config
    downstream so ``wardline.yaml`` severity overrides still apply.
    """

    boundary_types: tuple[BoundaryType, ...]
    rules: tuple[type[_Rule], ...]

    def extend(
        self,
        *,
        boundary_types: tuple[BoundaryType, ...] = (),
        rules: tuple[type[_Rule], ...] = (),
    ) -> TrustGrammar:
        """Append agent-defined types/rules to the defaults (append, never replace).

        Builtins are preloaded defaults (program spec T2.2); extensions are added
        after them, preserving builtin order and behavior.
        """
        return TrustGrammar(
            self.boundary_types + tuple(boundary_types),
            self.rules + tuple(rules),
        )


def default_grammar() -> TrustGrammar:
    """The builtin grammar: the 3 boundary types + the 4 rule classes, in today's
    exact order. The byte-identity oracle (design spec §5) pins this == today."""
    # Local import to avoid an import cycle (rules/__init__ -> rule modules; this
    # module is imported by the provider, which rules do not import).
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return TrustGrammar(BUILTIN_BOUNDARY_TYPES, BUILTIN_RULE_CLASSES)
