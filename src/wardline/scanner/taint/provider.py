# src/wardline/scanner/taint/provider.py
"""The pluggable taint-source seam consumed by L1 function seeding.

A ``TaintSourceProvider`` answers one question: what taint did the author
*declare* for this function (via decorators, annotations, or config)? SP1 ships
only the trivial ``DefaultTaintSourceProvider`` (no opinion on anything, so
callers fall back to ``UNKNOWN_RAW``). SP2 supplies the real
decorator-vocabulary provider via the rule registry.

The seam is intentionally extensible: providers may add fields to ``SeedContext``
and ``FunctionTaint`` freely. ``taint_for`` returns a :class:`SeedResult` (the
declared taint plus an optional unprovable-custom-boundary signal — Track 2 T2.4).
``SeedContext`` is kept minimal here (module name + alias map) — fields are added
when a provider actually consumes them, not speculatively.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity


@dataclass(frozen=True, slots=True)
class SeedContext:
    """Per-file context handed to a provider for each entity in that file.

    ``alias_map`` is the file's ``{local_name: fully_qualified_name}`` import
    map (from ``build_import_alias_map``); a provider uses it to resolve aliased
    decorator names against the trust vocabulary. ``project_modules`` is the set of
    dotted module names discovered in the scanned project; a provider uses it to
    fail closed for BUILTIN markers when the project shadows a builtin marker root
    (e.g. ships its own ``wardline``/``loom_markers`` package). Both default to
    empty so callers that do not seed from decorators (e.g. the trivial default
    provider's tests) need not supply them.
    """

    module: str
    alias_map: Mapping[str, str] = field(default_factory=dict)
    project_modules: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class FunctionTaint:
    """A provider's declared taint for one function: the taint observed INSIDE
    the body (input tier) and the taint of its return value (output tier)."""

    body_taint: TaintState
    return_taint: TaintState


@dataclass(frozen=True, slots=True)
class SeedResult:
    """A provider's per-entity result (Track 2 T2.4).

    ``taint`` is the declared seed (or ``None`` for 'no opinion', preserving the
    fail-closed ``UNKNOWN_RAW`` L1 fallback). ``unprovable_boundaries`` is the
    ``canonical_name``\\ s of every matched-but-UNPROVABLE *custom* boundary type on
    the function — the analyzer turns each into an observable
    ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` FACT. Builtin boundary types NEVER appear here
    (they stay silently fail-closed), preserving the byte-identity oracle (spec §4).

    Invariant (no false-green): when an unprovable custom boundary co-occurs with a
    PROVABLE decorator, ``taint`` is dragged to the fail-closed ``UNKNOWN_RAW`` meet
    (the provider must not let the provable one silently over-trust the function) and
    the unprovable names are still reported here.
    """

    taint: FunctionTaint | None
    unprovable_boundaries: tuple[str, ...] = ()


@runtime_checkable
class TaintSourceProvider(Protocol):
    """Maps a function entity to a :class:`SeedResult` (its declared taint, or
    ``taint=None`` for 'no opinion', plus an optional unprovable-boundary signal)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult: ...

    def fingerprint(self) -> str:
        """A stable string identifying this provider's *declaration surface*.

        Bound into the summary cache key so that a change in out-of-source
        declarations (SP2's decorator vocabulary, config-declared taints) — which
        a per-module source hash cannot observe — invalidates affected summaries.
        Constant for the SP1 default provider; SP2's provider derives it from its
        loaded vocabulary/config.
        """
        ...


class DefaultTaintSourceProvider:
    """The trivial provider: declares nothing. With no decorator vocabulary in
    SP1, every function falls back to ``UNKNOWN_RAW`` (fail-closed)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult:
        return SeedResult(taint=None)

    def fingerprint(self) -> str:
        return "default-v1"
